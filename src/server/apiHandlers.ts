/**
 * Manipuladores Web-Standard compartilhados para todas as rotas /api/* do PorttoHub.
 * Compatível com Cloudflare Workers (src/worker.ts) e Express Node.js (server.ts).
 */

import { GoogleGenAI, Type, ThinkingLevel } from '@google/genai';
import {
  authenticateRequest,
  getSupabaseServerConfig,
  isCondominioAutorizado,
  isValidUuid,
  podeGerenciarOperadores,
  resolvePublicSupabaseConfig,
  temPermissaoModuloBackend,
  type AuthContext
} from './authMiddleware';
import { buildTenantCacheKey, createUpstashCache, type RuntimeEnv } from './upstashClient';
import { validarRegraPasseQR } from '../services/passeQrValidation';

const OFICIAL_GITHUB_REPO = 'PorttoHub02/PorttoHubPro';
const EMAIL_REGEX = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

function getFetchFn(env: RuntimeEnv): typeof fetch {
  return typeof (env as any)?.__fetchImpl === 'function' ? (env as any).__fetchImpl : fetch;
}

const ALLOWED_OCR_MIME_TYPES = new Set(['image/jpeg', 'image/jpg', 'image/png', 'image/webp']);
const MAX_OCR_IMAGE_BYTES = 5 * 1024 * 1024; // 5 MB

// Allowlist explícita de tabelas que podem ser consultadas via proxy cache
const ALLOWED_CACHE_TABLES = new Set([
  'condominios',
  'operadores',
  'moradores',
  'encomendas_itens',
  'custodia',
  'chaves',
  'bancada_volumes',
  'registros_acesso',
  'entregadores',
  'materiais_posto',
  'rondas_pontos',
  'rondas',
  'ocorrencias',
  'prestadores',
  'configuracoes',
  'niveis_acesso',
  'reservas_areas',
  'areas_comuns',
  'manutencoes',
  'lembretes_portaria'
]);

const GLOBAL_TABLE_WITHOUT_CONDO_ID = new Set(['condominios']);

function verificarPermissaoTabelaCache(ctx: AuthContext, table: string, condominioId?: string): boolean {
  if (ctx.eAdminGlobal) return true;
  switch (table) {
    case 'condominios':
      return ctx.operador?.ativo !== false;
    case 'configuracoes':
    case 'niveis_acesso':
    case 'lembretes_portaria':
      return isCondominioAutorizado(ctx, condominioId);
    case 'operadores':
      return (
        podeGerenciarOperadores(ctx, condominioId) &&
        temPermissaoModuloBackend(ctx, 'cadastros', 'visualizar_operadores', condominioId)
      );
    case 'moradores':
      return (
        temPermissaoModuloBackend(ctx, 'cadastros', 'visualizar_moradores', condominioId) ||
        temPermissaoModuloBackend(ctx, 'moradores', 'visualizar', condominioId)
      );
    case 'encomendas_itens':
    case 'entregadores':
      return temPermissaoModuloBackend(ctx, 'encomendas', 'visualizar', condominioId);
    case 'custodia':
      return temPermissaoModuloBackend(ctx, 'custodia', 'visualizar', condominioId);
    case 'chaves':
      return temPermissaoModuloBackend(ctx, 'chaves', 'visualizar', condominioId);
    case 'bancada_volumes':
      return temPermissaoModuloBackend(ctx, 'bancada', 'visualizar', condominioId);
    case 'registros_acesso':
      return temPermissaoModuloBackend(ctx, 'controle_acesso', 'visualizar', condominioId);
    case 'materiais_posto':
      return temPermissaoModuloBackend(ctx, 'materiais', 'visualizar', condominioId);
    case 'rondas_pontos':
    case 'rondas':
      return temPermissaoModuloBackend(ctx, 'rondas', 'visualizar', condominioId);
    case 'ocorrencias':
      return temPermissaoModuloBackend(ctx, 'ocorrencias', 'visualizar', condominioId);
    case 'prestadores':
      return temPermissaoModuloBackend(ctx, 'autorizados', 'visualizar', condominioId);
    case 'reservas_areas':
    case 'areas_comuns':
      return temPermissaoModuloBackend(ctx, 'reservas', 'visualizar', condominioId);
    case 'manutencoes':
      return temPermissaoModuloBackend(ctx, 'manutencao', 'visualizar', condominioId);
    default:
      return false;
  }
}

// Rate limit simples em memória por usuário (30 requisições / 60s)
const ocrRateMap = new Map<string, { count: number; resetAt: number }>();

function checkOcrRateLimit(userId: string): boolean {
  const now = Date.now();
  const entry = ocrRateMap.get(userId);
  if (!entry || now > entry.resetAt) {
    ocrRateMap.set(userId, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (entry.count >= 30) {
    return false;
  }
  entry.count += 1;
  return true;
}

export function jsonResponse(data: any, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders
    }
  });
}

async function readJsonBody(request: Request): Promise<any> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// Cache em memória para versão do repositório (15 minutos)
let cachedVersaoData: any = null;
let cachedVersaoTimestamp = 0;
const VERSAO_CACHE_TTL_MS = 15 * 60 * 1000;

export function handleEnvConfigJs(env: RuntimeEnv): Response {
  const pub = resolvePublicSupabaseConfig(env);
  const payload: Record<string, any> = {
    SUPABASE_URL: pub.url,
    SUPABASE_ANON_KEY: pub.publicKey,
    VITE_SUPABASE_URL: pub.url,
    VITE_SUPABASE_ANON_KEY: pub.publicKey,
    configured: pub.configured
  };
  if (pub.keySource === 'SUPABASE_PUBLISHABLE_KEY' && pub.publicKey) {
    payload.SUPABASE_PUBLISHABLE_KEY = pub.publicKey;
  }

  return new Response(`window.__PORTTOHUB_PUBLIC_ENV__ = ${JSON.stringify(payload)};`, {
    status: 200,
    headers: {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
      Pragma: 'no-cache',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

export async function handleHealth(env: RuntimeEnv, runtimeName: 'node' | 'cloudflare-worker'): Promise<Response> {
  const pub = resolvePublicSupabaseConfig(env);
  const sb = getSupabaseServerConfig(env);
  const cache = createUpstashCache(env);

  const missingVariables: string[] = [];
  if (!pub.urlValid) {
    missingVariables.push('SUPABASE_URL (ou VITE_SUPABASE_URL)');
  }
  if (!pub.publicKeyValid) {
    missingVariables.push('SUPABASE_PUBLISHABLE_KEY (ou SUPABASE_ANON_KEY / VITE_SUPABASE_ANON_KEY)');
  }

  return jsonResponse({
    ok: true,
    workerWorking: true,
    service: 'porttohub-api',
    runtime: runtimeName,
    timestamp: new Date().toISOString(),
    configured: {
      supabase: sb.configured,
      supabaseUrlValid: pub.urlValid,
      supabasePublicKey: pub.publicKeyValid,
      supabaseAdmin: Boolean(sb.configured && sb.serviceRoleKey),
      frontendConfigReady: pub.configured,
      upstashRedis: cache.isConfigured(),
      geminiOcr: Boolean(env.GEMINI_API_KEY)
    },
    diagnostics: {
      workerStatus: 'ok',
      supabaseUrl: {
        configured: pub.urlPresent,
        valid: pub.urlValid,
        source: pub.urlSource,
        acceptedVariables: ['SUPABASE_URL', 'VITE_SUPABASE_URL'],
        missing: pub.urlValid ? null : 'SUPABASE_URL (ou VITE_SUPABASE_URL)'
      },
      supabasePublicKey: {
        configured: pub.publicKeyValid,
        source: pub.keySource,
        acceptedVariables: ['SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_ANON_KEY', 'VITE_SUPABASE_ANON_KEY'],
        missing: pub.publicKeyValid
          ? null
          : 'SUPABASE_PUBLISHABLE_KEY (ou SUPABASE_ANON_KEY / VITE_SUPABASE_ANON_KEY)'
      },
      frontendEnvConfig: {
        endpoint: '/env-config.js',
        loaded: pub.configured,
        ready: pub.configured
      },
      missingVariables
    }
  });
}

export async function handleGithubVersao(env: RuntimeEnv, localGitInfo?: {
  sha?: string;
  mensagem?: string;
  autor?: string;
  dataIso?: string;
}): Promise<Response> {
  try {
    const agora = Date.now();
    if (cachedVersaoData && agora - cachedVersaoTimestamp < VERSAO_CACHE_TTL_MS) {
      return jsonResponse(cachedVersaoData);
    }

    let remoteCommit: any = null;
    try {
      const token = String(env.GITHUB_TOKEN || '').trim();
      const headers: Record<string, string> = {
        'User-Agent': 'PorttoHub-App',
        Accept: 'application/vnd.github.v3+json'
      };
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }

      const controller = new AbortController();
      const fetchTimeout = setTimeout(() => controller.abort(), 2500);
      const ghRes = await fetch(`https://api.github.com/repos/${OFICIAL_GITHUB_REPO}/commits/main`, {
        headers,
        signal: controller.signal
      });
      clearTimeout(fetchTimeout);
      if (ghRes.ok) {
        remoteCommit = await ghRes.json();
      }
    } catch {}

    const sha = remoteCommit ? String(remoteCommit.sha).slice(0, 7) : localGitInfo?.sha || 'main';
    const rawDate = remoteCommit ? remoteCommit.commit?.committer?.date : localGitInfo?.dataIso || new Date().toISOString();
    const mensagem = remoteCommit ? remoteCommit.commit?.message : localGitInfo?.mensagem || 'PorttoHub Pro';
    const autor = remoteCommit ? remoteCommit.commit?.author?.name : localGitInfo?.autor || 'PorttoHub';

    const dataObj = new Date(rawDate);
    const dataBrasilia = new Intl.DateTimeFormat('pt-BR', {
      timeZone: 'America/Sao_Paulo',
      dateStyle: 'short',
      timeStyle: 'medium'
    }).format(dataObj);

    const partes = new Intl.DateTimeFormat('pt-BR', {
      timeZone: 'America/Sao_Paulo',
      day: '2-digit',
      month: '2-digit',
      year: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    }).formatToParts(dataObj);
    const mapa: Record<string, string> = {};
    for (const p of partes) mapa[p.type] = p.value;
    const versaoCalculada = `${mapa.day || '01'}${mapa.month || '01'}${(mapa.year || '26').slice(-2)}${mapa.hour || '00'}${mapa.minute || '00'}`;

    const payload = {
      sucesso: true,
      repositorio: OFICIAL_GITHUB_REPO,
      branch: 'main',
      sha,
      mensagem,
      autor,
      dataIso: rawDate,
      dataBrasilia: `${dataBrasilia} (Horário de Brasília - BRT)`,
      versaoCalculada,
      horarioConsulta: new Date().toLocaleTimeString('pt-BR', { timeZone: 'America/Sao_Paulo' })
    };

    cachedVersaoData = payload;
    cachedVersaoTimestamp = agora;
    return jsonResponse(payload);
  } catch (err: any) {
    if (cachedVersaoData) return jsonResponse(cachedVersaoData);
    return jsonResponse({ sucesso: false, erro: err?.message || 'Erro ao consultar versão' }, 500);
  }
}

/**
 * OCR EXCLUSIVO de Etiquetas de Encomendas (< 5s).
 * Exige JWT válido, aplica rate limit, valida MIME/tamanho e nunca extrai DANFE de 44 dígitos.
 */
export async function handleOcrEtiqueta(request: Request, env: RuntimeEnv): Promise<Response> {
  const auth = await authenticateRequest(request, env);
  if (!auth.ok) {
    return jsonResponse({ erro: auth.error }, auth.status);
  }

  if (
    !temPermissaoModuloBackend(auth.context, 'encomendas', 'criar') &&
    !temPermissaoModuloBackend(auth.context, 'encomendas', 'entrada_lote') &&
    !temPermissaoModuloBackend(auth.context, 'encomendas', 'triagem')
  ) {
    return jsonResponse({ erro: 'Sem permissão no módulo Encomendas para leitura OCR de etiquetas.' }, 403);
  }

  if (!checkOcrRateLimit(auth.context.authUser.id)) {
    return jsonResponse({ erro: 'Limite de leituras de etiquetas atingido. Aguarde alguns segundos.' }, 429);
  }

  const body = await readJsonBody(request);
  const imagemBase64 = body?.imagemBase64;
  if (!imagemBase64 || typeof imagemBase64 !== 'string') {
    return jsonResponse({ erro: 'Imagem não fornecida.' }, 400);
  }

  const mimeMatch = imagemBase64.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,(.+)$/);
  const mimeTypeRaw = (mimeMatch?.[1] || 'image/jpeg').toLowerCase();
  if (!ALLOWED_OCR_MIME_TYPES.has(mimeTypeRaw)) {
    return jsonResponse({ erro: 'Formato de imagem não permitido. Use JPEG, PNG ou WEBP.' }, 400);
  }

  const base64Data = mimeMatch ? mimeMatch[2] : imagemBase64.replace(/^data:image\/\w+;base64,/, '');
  const approxBytes = Math.ceil((base64Data.length * 3) / 4);
  if (approxBytes > MAX_OCR_IMAGE_BYTES) {
    return jsonResponse({ erro: 'Imagem excede o limite de 5MB.' }, 413);
  }

  const apiKey = String(env.GEMINI_API_KEY || '').trim();
  if (!apiKey) {
    return jsonResponse({ erro: 'Chave GEMINI_API_KEY não configurada no servidor.' }, 503);
  }

  try {
    const ai = new GoogleGenAI({ apiKey });
    const modelName = String(env.GEMINI_OCR_MODEL || 'gemini-4-hydrogen').trim();

    const systemInstruction = `Você é um leitor óptico ultra-rápido de etiquetas de logística brasileira (Correios, Mercado Livre, Shopee, Amazon, Jadlog, Loggi).
RESPONDA EM MENOS DE 2 SEGUNDOS.

REGRAS RÍGIDAS:
1. "codigoRastreio": Código de rastreamento principal (ex: Correios "NL123456789BR", Mercado Livre "MLB...", Shopee "BR24...", Amazon "TBA...").
2. "numeroNF": Número da NOTA FISCAL impresso na etiqueta (ex: "NF 123456", "NF-e: 001.234.567"). Retorne apenas o número curto.
3. PROIBIDO EXTRAIR CHAVE DE ACESSO DANFE: NUNCA retorne a chave de acesso de 44 dígitos da NF-e.
4. "destinatario": Nome da pessoa destinatária se legível.
5. "unidade": Número do apartamento ou casa.
6. "bloco": Bloco ou torre se legível.
7. "transportadora": Nome da empresa (Correios, Mercado Livre, Shopee, Amazon, Jadlog, etc.).
8. "outroCodigo": Apenas 1 outro código curto alternativo caso exista.`;

    const abortController = new AbortController();
    const timeoutId = setTimeout(() => abortController.abort(), 4500);

    const response = await ai.models.generateContent({
      model: modelName,
      contents: [
        {
          role: 'user',
          parts: [
            {
              inlineData: {
                data: base64Data,
                mimeType: mimeTypeRaw === 'image/jpg' ? 'image/jpeg' : mimeTypeRaw
              }
            },
            {
              text: 'Extraia rapidamente o código de rastreio e o número da Nota Fiscal (NF). NÃO extraia chave de 44 dígitos da DANFE.'
            }
          ]
        }
      ],
      config: {
        systemInstruction,
        abortSignal: abortController.signal,
        responseMimeType: 'application/json',
        maxOutputTokens: 250,
        thinkingConfig: {
          thinkingLevel: ThinkingLevel.LOW
        },
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            codigoRastreio: { type: Type.STRING },
            numeroNF: { type: Type.STRING },
            destinatario: { type: Type.STRING },
            unidade: { type: Type.STRING },
            bloco: { type: Type.STRING },
            transportadora: { type: Type.STRING },
            outroCodigo: { type: Type.STRING }
          }
        }
      }
    });

    clearTimeout(timeoutId);

    const parsed = JSON.parse(response.text || '{}');
    const sugestoes: Array<{ tipo: 'rastreio' | 'nf' | 'outro'; label: string; valor: string; destaque?: boolean }> = [];
    const ehChaveDanfe = (cod: string) => cod.replace(/\D/g, '').length >= 35;

    const codRastreio = (parsed.codigoRastreio || '').trim();
    if (codRastreio && !ehChaveDanfe(codRastreio) && codRastreio !== 'null' && codRastreio !== 'undefined') {
      sugestoes.push({
        tipo: 'rastreio',
        label: `Rastreio (${parsed.transportadora || 'Pacote'})`,
        valor: codRastreio,
        destaque: true
      });
    }

    const numNF = (parsed.numeroNF || '').trim();
    if (numNF && !ehChaveDanfe(numNF) && numNF !== 'null' && numNF !== 'undefined' && numNF !== codRastreio) {
      sugestoes.push({
        tipo: 'nf',
        label: 'Nota Fiscal (NF)',
        valor: numNF,
        destaque: true
      });
    }

    const outroCod = (parsed.outroCodigo || '').trim();
    if (
      outroCod &&
      !ehChaveDanfe(outroCod) &&
      outroCod !== 'null' &&
      outroCod !== 'undefined' &&
      outroCod !== codRastreio &&
      outroCod !== numNF &&
      sugestoes.length < 3
    ) {
      sugestoes.push({
        tipo: 'outro',
        label: 'Cód. Alternativo',
        valor: outroCod
      });
    }

    return jsonResponse({
      codigoRastreio: codRastreio,
      numeroNF: numNF,
      destinatario: (parsed.destinatario || '').trim(),
      unidade: (parsed.unidade || '').trim(),
      bloco: (parsed.bloco || '').trim(),
      transportadora: (parsed.transportadora || '').trim(),
      sugestoes: sugestoes.slice(0, 3),
      confianca: 99,
      metodoUtilizado: 'IA_GEMINI_FAST'
    });
  } catch (err: any) {
    console.error('[API OCR Etiqueta] Erro:', err?.message || err);
    return jsonResponse({ erro: err?.message || 'Falha no processamento OCR da etiqueta.' }, 500);
  }
}

/**
 * Provisionamento seguro de credenciais de operadores no Supabase Auth (server-only Service Role).
 * Garante isolamento multi-tenant estrito e impede alteração de contas globais ou de outros condomínios.
 */
export async function handleAdminProvisionarOperador(request: Request, env: RuntimeEnv): Promise<Response> {
  const auth = await authenticateRequest(request, env);
  if (!auth.ok) {
    return jsonResponse({ error: auth.error }, auth.status);
  }

  const cfg = getSupabaseServerConfig(env);
  if (!cfg.configured || !cfg.serviceRoleKey) {
    return jsonResponse(
      { error: 'SUPABASE_SERVICE_ROLE_KEY não configurada no servidor. Configure nos Secrets do servidor.' },
      503
    );
  }

  const body = await readJsonBody(request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return jsonResponse({ error: 'Corpo da requisição inválido.' }, 400);
  }

  const operadorIdAlvo = body.operador_id ? String(body.operador_id).trim() : '';
  const authUserIdInformado = body.auth_user_id ? String(body.auth_user_id).trim() : '';
  const email = String(body.email || '').trim().toLowerCase();
  const password = body.password !== undefined && body.password !== null ? String(body.password) : '';
  const nome = String(body.nome || '').trim();
  const targetCondominioId = body.condominio_id ? String(body.condominio_id).trim() : '';

  if (operadorIdAlvo && !isValidUuid(operadorIdAlvo)) {
    return jsonResponse({ error: 'Parâmetro operador_id inválido.' }, 400);
  }
  if (authUserIdInformado && !isValidUuid(authUserIdInformado)) {
    return jsonResponse({ error: 'Parâmetro auth_user_id inválido.' }, 400);
  }
  if (email && !EMAIL_REGEX.test(email)) {
    return jsonResponse({ error: 'Formato de e-mail inválido.' }, 400);
  }
  if (password && (password.length < 6 || password.length > 128)) {
    return jsonResponse({ error: 'A senha deve possuir entre 6 e 128 caracteres.' }, 400);
  }

  const perfilSolicitado = String(body.perfil || '').trim().toLowerCase();
  const nivelSolicitado = body.nivel_acesso !== undefined && body.nivel_acesso !== null ? Number(body.nivel_acesso) : null;

  if (!auth.context.eAdminGlobal) {
    if (body.acesso_global_condominios === true || body.global === true || perfilSolicitado === 'admin_geral' || nivelSolicitado === 0) {
      return jsonResponse(
        { error: 'Administrador de condomínio não pode conceder acesso global nem criar Administrador Geral.' },
        403
      );
    }
    if (!isValidUuid(targetCondominioId)) {
      return jsonResponse({ error: 'Condomínio de destino obrigatório e deve ser um UUID válido.' }, 400);
    }
    if (!podeGerenciarOperadores(auth.context, targetCondominioId)) {
      return jsonResponse({ error: 'Sem permissão para provisionar operadores neste condomínio.' }, 403);
    }
    const acaoOperador = operadorIdAlvo ? 'editar_operadores' : 'operadores';
    if (!temPermissaoModuloBackend(auth.context, 'cadastros', acaoOperador, targetCondominioId)) {
      return jsonResponse({ error: 'Operador sem permissão funcional no módulo Cadastros (operadores).' }, 403);
    }
    if (operadorIdAlvo && operadorIdAlvo === auth.context.operador.id) {
      return jsonResponse(
        { error: 'Administrador de condomínio não pode alterar seu próprio perfil, privilégios ou vínculo pelo endpoint administrativo.' },
        403
      );
    }
    if (authUserIdInformado && !operadorIdAlvo) {
      return jsonResponse(
        { error: 'Gestor local não pode alterar usuário diretamente por auth_user_id; informe um operador_id existente do seu condomínio.' },
        403
      );
    }
  }

  const fetchFn = getFetchFn(env);
  const adminHeaders = {
    apikey: cfg.serviceRoleKey,
    Authorization: `Bearer ${cfg.serviceRoleKey}`,
    'Content-Type': 'application/json'
  };

  let opTarget: any = null;
  let authUserIdExistente = auth.context.eAdminGlobal ? authUserIdInformado : '';

  if (operadorIdAlvo) {
    const opRes = await fetchFn(
      `${cfg.url}/rest/v1/operadores?select=id,condominio_id,auth_user_id,acesso_global_condominios,email,perfil,nivel_acesso&id=eq.${encodeURIComponent(operadorIdAlvo)}&limit=1`,
      { headers: adminHeaders }
    );
    if (!opRes.ok) {
      return jsonResponse({ error: 'Falha ao verificar operador-alvo na base.' }, 502);
    }

    const opRows: any[] = await opRes.json();
    opTarget = opRows?.[0] || null;

    if (!opTarget) {
      return jsonResponse({ error: 'Operador-alvo não encontrado na base.' }, 404);
    }

    if (!auth.context.eAdminGlobal) {
      if (opTarget.acesso_global_condominios === true || String(opTarget.perfil || '').toLowerCase() === 'admin_geral') {
        return jsonResponse({ error: 'Administrador de condomínio não pode alterar contas administrativas globais.' }, 403);
      }
      if (String(opTarget.condominio_id || '').trim() !== String(auth.context.operador.condominio_id || '').trim()) {
        return jsonResponse({ error: 'Não autorizado a alterar ou transferir operador de outro condomínio.' }, 403);
      }
      if (String(opTarget.condominio_id || '').trim() !== targetCondominioId) {
        return jsonResponse({ error: 'O condomínio informado diverge do condomínio real do operador-alvo.' }, 403);
      }
    }

    if (opTarget.auth_user_id) {
      if (auth.context.eAdminGlobal && authUserIdInformado && authUserIdInformado !== String(opTarget.auth_user_id)) {
        return jsonResponse({ error: 'auth_user_id informado diverge do vínculo real do operador-alvo.' }, 403);
      }
      authUserIdExistente = String(opTarget.auth_user_id);
    } else if (!auth.context.eAdminGlobal) {
      authUserIdExistente = '';
    }
  } else if (authUserIdExistente && auth.context.eAdminGlobal) {
    // Mesmo para admin global, confirma se auth_user_id é válido antes de atualizar
    authUserIdExistente = authUserIdInformado;
  }

  if (!email && !authUserIdExistente) {
    return jsonResponse({ error: 'Informe um e-mail válido para criar ou atualizar o acesso Auth.' }, 400);
  }

  const vincularOperadorNoBanco = async (finalAuthUserId: string): Promise<Response | null> => {
    if (!operadorIdAlvo || !opTarget) return null;
    const authDivergente = String(opTarget.auth_user_id || '').trim() !== String(finalAuthUserId).trim();
    const emailDivergente = Boolean(email && String(opTarget.email || '').trim().toLowerCase() !== email);
    if (!authDivergente && !emailDivergente) return null;

    const patchPayload: Record<string, any> = {
      auth_user_id: finalAuthUserId,
      migrado_auth_em: new Date().toISOString()
    };
    if (email) {
      patchPayload.email = email;
    }

    const patchOpRes = await fetchFn(
      `${cfg.url}/rest/v1/operadores?id=eq.${encodeURIComponent(operadorIdAlvo)}`,
      {
        method: 'PATCH',
        headers: {
          ...adminHeaders,
          Prefer: 'return=representation'
        },
        body: JSON.stringify(patchPayload)
      }
    );
    if (!patchOpRes.ok) {
      const patchErrText = await patchOpRes.text().catch(() => '');
      return jsonResponse(
        {
          error: `Conta Auth processada, mas falhou ao vincular auth_user_id na tabela operadores: ${patchErrText || patchOpRes.status}`
        },
        502
      );
    }
    return null;
  };

  try {
    // 1. Atualização de usuário Auth existente
    if (authUserIdExistente && isValidUuid(authUserIdExistente)) {
      const updatePayload: any = { email_confirm: true };
      if (email) updatePayload.email = email;
      if (password) updatePayload.password = password;
      if (nome) updatePayload.user_metadata = { nome };

      const updRes = await fetchFn(`${cfg.url}/auth/v1/admin/users/${encodeURIComponent(authUserIdExistente)}`, {
        method: 'PUT',
        headers: adminHeaders,
        body: JSON.stringify(updatePayload)
      });
      const updJson: any = await updRes.json().catch(() => ({}));
      if (!updRes.ok) {
        return jsonResponse({ error: updJson?.msg || updJson?.message || 'Erro ao atualizar usuário no Supabase Auth.' }, updRes.status);
      }
      const finalAuthId = String(updJson?.id || authUserIdExistente);
      const linkErrRes = await vincularOperadorNoBanco(finalAuthId);
      if (linkErrRes) return linkErrRes;

      const cache = createUpstashCache(env);
      await cache.invalidateByTag('table:operadores');
      if (targetCondominioId) {
        await cache.invalidateByPattern(`porttohub:v1:condo:${targetCondominioId}:operadores:*`);
      }
      return jsonResponse({
        sucesso: true,
        auth_user_id: finalAuthId,
        operador_vinculado: Boolean(operadorIdAlvo),
        acao: 'atualizado'
      });
    }

    // 2. Criação de novo usuário Auth — antes verifica se e-mail já pertence a operador existente na base
    if (!password) {
      return jsonResponse({ error: 'Informe uma senha inicial de acesso (mínimo 6 caracteres).' }, 400);
    }

    if (email) {
      const existingOpByEmailRes = await fetchFn(
        `${cfg.url}/rest/v1/operadores?select=id,condominio_id,auth_user_id,acesso_global_condominios,perfil&email=ilike.${encodeURIComponent(email)}&limit=5`,
        { headers: adminHeaders }
      );
      if (!existingOpByEmailRes.ok) {
        return jsonResponse({ error: 'Falha ao validar unicidade de e-mail na tabela de operadores.' }, 502);
      }
      const existingRows: any[] = await existingOpByEmailRes.json();
      if (Array.isArray(existingRows) && existingRows.length > 0) {
        const conflitoOutro = existingRows.find(r => r.id !== operadorIdAlvo);
        if (conflitoOutro) {
          if (!auth.context.eAdminGlobal) {
            if (
              conflitoOutro.acesso_global_condominios === true ||
              String(conflitoOutro.perfil || '').toLowerCase() === 'admin_geral' ||
              String(conflitoOutro.condominio_id || '').trim() !== String(auth.context.operador.condominio_id || '').trim()
            ) {
              return jsonResponse(
                { error: 'Não autorizado: este e-mail já pertence a um operador global ou de outro condomínio.' },
                403
              );
            }
          }
          if (!operadorIdAlvo) {
            return jsonResponse(
              { error: 'Já existe operador cadastrado com este e-mail; informe operador_id existente para atualizar suas credenciais.' },
              409
            );
          }
        }
      }
    }

    const createRes = await fetchFn(`${cfg.url}/auth/v1/admin/users`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({
        email,
        password,
        email_confirm: true,
        user_metadata: nome ? { nome } : undefined
      })
    });
    const createJson: any = await createRes.json().catch(() => ({}));

    if (createRes.ok && createJson?.id) {
      const finalAuthId = String(createJson.id);
      const linkErrRes = await vincularOperadorNoBanco(finalAuthId);
      if (linkErrRes) return linkErrRes;

      const cache = createUpstashCache(env);
      await cache.invalidateByTag('table:operadores');
      if (targetCondominioId) {
        await cache.invalidateByPattern(`porttohub:v1:condo:${targetCondominioId}:operadores:*`);
      }
      return jsonResponse({
        sucesso: true,
        auth_user_id: finalAuthId,
        operador_vinculado: Boolean(operadorIdAlvo),
        acao: 'criado'
      });
    }

    // 3. Fallback quando o e-mail já existe no Auth: apenas Administrador Global pode sincronizar conta arbitrária,
    // ou gestor local SOMENTE se a conta Auth já pertencer ao operador_id autorizado em questão.
    const listRes = await fetchFn(
      `${cfg.url}/auth/v1/admin/users?page=1&per_page=50&filter=${encodeURIComponent(email)}`,
      { headers: adminHeaders }
    );
    if (listRes.ok) {
      const listJson: any = await listRes.json();
      const users = Array.isArray(listJson?.users) ? listJson.users : [];
      const found = users.find((u: any) => String(u.email || '').toLowerCase() === email);
      if (found?.id) {
        const ownerRes = await fetchFn(
          `${cfg.url}/rest/v1/operadores?select=id,condominio_id,acesso_global_condominios&auth_user_id=eq.${encodeURIComponent(found.id)}&limit=1`,
          { headers: adminHeaders }
        );
        const ownerRows: any[] = ownerRes.ok ? await ownerRes.json() : [];
        const ownerOp = ownerRows?.[0];

        if (!auth.context.eAdminGlobal) {
          if (ownerOp) {
            if (ownerOp.acesso_global_condominios === true || !isCondominioAutorizado(auth.context, ownerOp.condominio_id)) {
              return jsonResponse(
                { error: 'Não autorizado a alterar senha de conta Auth vinculada a outro condomínio ou administrador global.' },
                403
              );
            }
          }
          if (!operadorIdAlvo || !opTarget || (ownerOp && ownerOp.id !== opTarget.id)) {
            return jsonResponse(
              { error: 'E-mail já cadastrado no Supabase Auth. Somente Administrador Global pode vincular conta Auth existente sem vínculo do mesmo operador.' },
              403
            );
          }
        }

        const syncRes = await fetchFn(`${cfg.url}/auth/v1/admin/users/${encodeURIComponent(found.id)}`, {
          method: 'PUT',
          headers: adminHeaders,
          body: JSON.stringify({
            password,
            email_confirm: true,
            user_metadata: nome ? { nome } : undefined
          })
        });
        if (syncRes.ok) {
          const finalAuthId = String(found.id);
          const linkErrRes = await vincularOperadorNoBanco(finalAuthId);
          if (linkErrRes) return linkErrRes;

          const cache = createUpstashCache(env);
          await cache.invalidateByTag('table:operadores');
          if (targetCondominioId) {
            await cache.invalidateByPattern(`porttohub:v1:condo:${targetCondominioId}:operadores:*`);
          }
          return jsonResponse({
            sucesso: true,
            auth_user_id: finalAuthId,
            operador_vinculado: Boolean(operadorIdAlvo),
            acao: 'vinculado_e_atualizado'
          });
        }
      }
    }

    return jsonResponse(
      { error: createJson?.msg || createJson?.message || 'Erro ao criar conta no Supabase Auth.' },
      createRes.status || 400
    );
  } catch (err: any) {
    return jsonResponse({ error: err?.message || 'Erro interno no provisionamento Auth.' }, 500);
  }
}

/**
 * Validação e consumo atômico de Passe Virtual QR (servidor).
 * Impede reutilização após max_usos, acesso fora da data/horário ou entre condomínios.
 */
export async function handleValidarPasseQR(request: Request, env: RuntimeEnv): Promise<Response> {
  const auth = await authenticateRequest(request, env);
  if (!auth.ok) {
    return jsonResponse({ valido: false, motivo: auth.error }, auth.status);
  }

  const body = await readJsonBody(request);
  const condominioId = body?.condominioId ? String(body.condominioId).trim() : '';
  const token = body?.token ? String(body.token).trim() : '';
  const consumir = Boolean(body?.consumir);
  const pontoAcesso = body?.pontoAcesso ? String(body.pontoAcesso).trim() : 'Portaria Principal (Pedestres)';

  if (!isValidUuid(condominioId)) {
    return jsonResponse({ valido: false, motivo: 'condominioId inválido.' }, 400);
  }
  if (!isCondominioAutorizado(auth.context, condominioId)) {
    return jsonResponse({ valido: false, motivo: 'Acesso negado a este condomínio.' }, 403);
  }
  const acaoQr = consumir ? 'liberar_entrada' : 'visualizar';
  if (!temPermissaoModuloBackend(auth.context, 'controle_acesso', acaoQr, condominioId)) {
    return jsonResponse({ valido: false, motivo: 'Acesso negado: operador sem permissão no módulo Controle de Acesso.' }, 403);
  }
  if (!token) {
    return jsonResponse({ valido: false, motivo: 'Código do Passe Virtual não informado.' }, 400);
  }

  const cfg = getSupabaseServerConfig(env);
  const fetchFn = getFetchFn(env);
  const userHeaders = {
    apikey: cfg.anonKey,
    Authorization: `Bearer ${auth.context.jwt}`,
    'Content-Type': 'application/json'
  };
  const fallbackHeaders = cfg.serviceRoleKey
    ? {
        apikey: cfg.serviceRoleKey,
        Authorization: `Bearer ${cfg.serviceRoleKey}`,
        'Content-Type': 'application/json'
      }
    : userHeaders;

  try {
    // 1. Tenta RPC transacional atômica no PostgreSQL (FOR UPDATE)
    const rpcRes = await fetchFn(`${cfg.url}/rest/v1/rpc/validar_e_consumir_passe_qr`, {
      method: 'POST',
      headers: userHeaders,
      body: JSON.stringify({
        p_condominio_id: condominioId,
        p_token: token,
        p_consumir: consumir,
        p_ponto_acesso: pontoAcesso,
        p_operador_nome: auth.context.operador.nome || auth.context.operador.login || 'Portaria'
      })
    });

    if (rpcRes.ok) {
      const rpcJson: any = await rpcRes.json();
      return jsonResponse(rpcJson, rpcJson?.valido ? 200 : 400);
    }

    const rpcErrText = await rpcRes.text().catch(() => '');
    const isRpcMissing =
      rpcRes.status === 404 &&
      (rpcErrText.includes('PGRST202') || rpcErrText.toLowerCase().includes('could not find the function'));

    if (!isRpcMissing) {
      return jsonResponse(
        {
          valido: false,
          motivo: 'Falha na validação transacional do Passe Virtual no servidor.'
        },
        rpcRes.status >= 400 && rpcRes.status < 500 ? rpcRes.status : 502
      );
    }

    // 2. Fallback CAS permitido exclusivamente quando a função RPC ainda não existe (404 PGRST202)
    const tokenLimpo = token.toUpperCase();
    const filtroToken = isValidUuid(token)
      ? `or=(token.ilike.${encodeURIComponent(tokenLimpo)},id.eq.${encodeURIComponent(token)})`
      : `token=ilike.${encodeURIComponent(tokenLimpo)}`;

    const passRes = await fetchFn(
      `${cfg.url}/rest/v1/passes_virtuais_qr?select=*&condominio_id=eq.${encodeURIComponent(condominioId)}&${filtroToken}&limit=1`,
      { headers: userHeaders }
    );
    if (!passRes.ok) {
      return jsonResponse({ valido: false, motivo: 'Falha ao consultar passe no servidor.' }, 502);
    }
    const rows: any[] = await passRes.json();
    const passe = rows?.[0];

    if (!passe) {
      return jsonResponse({ valido: false, motivo: 'Passe Virtual não encontrado neste condomínio.' }, 404);
    }

    const check = validarRegraPasseQR(passe);
    if (!check.valido) {
      return jsonResponse({ valido: false, passe, motivo: check.motivo }, 400);
    }

    if (!consumir) {
      return jsonResponse({ valido: true, passe }, 200);
    }

    const usosAtuais = Number(passe.usos_realizados || 0);
    const maxUsos = Math.max(1, Number(passe.max_usos || passe.limite_usos || 1));
    const novosUsos = usosAtuais + 1;
    const novoStatus = novosUsos >= maxUsos ? 'utilizado' : 'valido';

    const patchRes = await fetchFn(
      `${cfg.url}/rest/v1/passes_virtuais_qr?id=eq.${encodeURIComponent(passe.id)}&condominio_id=eq.${encodeURIComponent(condominioId)}&usos_realizados=eq.${usosAtuais}&status=eq.valido`,
      {
        method: 'PATCH',
        headers: {
          ...fallbackHeaders,
          Prefer: 'return=representation'
        },
        body: JSON.stringify({
          usos_realizados: novosUsos,
          status: novoStatus,
          updated_at: new Date().toISOString()
        })
      }
    );

    if (!patchRes.ok) {
      return jsonResponse({ valido: false, motivo: 'Erro ao registrar utilização do passe no servidor.' }, 502);
    }

    const updatedRows: any[] = await patchRes.json();
    if (!Array.isArray(updatedRows) || updatedRows.length === 0) {
      return jsonResponse(
        { valido: false, motivo: 'Passe já foi consumido simultaneamente ou atingiu o limite de utilizações.' },
        409
      );
    }

    const passeAtualizado = updatedRows[0];
    const regInsertRes = await fetchFn(`${cfg.url}/rest/v1/registros_acesso`, {
      method: 'POST',
      headers: {
        ...userHeaders,
        Prefer: 'return=representation'
      },
      body: JSON.stringify([{
        condominio_id: condominioId,
        tipo: passe.tipo === 'festa_convidado' ? 'convidado_evento' : (passe.tipo || 'visitante'),
        nome: passe.visitante_nome,
        documento: passe.visitante_documento || '',
        unidade_bloco: passe.unidade_bloco,
        morador_responsavel: passe.morador_nome,
        ponto_acesso_entrada: pontoAcesso,
        data_hora_entrada: new Date().toISOString(),
        status: 'presente',
        operador_entrada_nome: auth.context.operador.nome || auth.context.operador.login || 'Portaria',
        observacoes: `Liberado via Passe QR (${passe.token}) [Uso ${novosUsos}/${maxUsos}]`,
        passe_qr_id: passe.id
      }])
    });

    if (!regInsertRes.ok) {
      // Compensa uso se inserção do registro de entrada falhar
      await fetchFn(
        `${cfg.url}/rest/v1/passes_virtuais_qr?id=eq.${encodeURIComponent(passe.id)}&condominio_id=eq.${encodeURIComponent(condominioId)}`,
        {
          method: 'PATCH',
          headers: fallbackHeaders,
          body: JSON.stringify({ usos_realizados: usosAtuais, status: 'valido' })
        }
      ).catch(() => {});
      return jsonResponse({ valido: false, motivo: 'Falha ao gravar registro de acesso do passe.' }, 502);
    }

    const regRows: any[] = await regInsertRes.json();
    return jsonResponse({
      valido: true,
      consumido: true,
      passe: passeAtualizado,
      registro: regRows?.[0] || null
    }, 200);
  } catch (err: any) {
    return jsonResponse({ valido: false, motivo: err?.message || 'Erro interno ao validar Passe QR.' }, 500);
  }
}

export async function handleCacheQuery(request: Request, env: RuntimeEnv): Promise<Response> {
  const start = Date.now();
  const auth = await authenticateRequest(request, env);
  if (!auth.ok) {
    return jsonResponse({ erro: auth.error, data: [] }, auth.status);
  }

  const body = await readJsonBody(request);
  const {
    table,
    select = '*',
    filters = [],
    orderBy,
    limit,
    ttlSeconds = 180,
    forceRefresh = false,
    condominioId: rawCondoId
  } = body || {};

  if (!table || typeof table !== 'string' || !ALLOWED_CACHE_TABLES.has(table)) {
    return jsonResponse({ erro: 'Tabela não informada ou não permitida neste endpoint.', data: [] }, 400);
  }

  const filtersList = Array.isArray(filters) ? [...filters] : [];
  const condoIdFromFilters = filtersList.find(
    f => f.field === 'condominio_id' && f.value && f.value !== 'todos' && f.value !== 'global'
  )?.value;
  const headerCondo = request.headers.get('x-condominio-id') || '';
  const candidateCondoId =
    (rawCondoId && rawCondoId !== 'todos' && rawCondoId !== 'global' ? String(rawCondoId) : '') ||
    (condoIdFromFilters ? String(condoIdFromFilters) : '') ||
    (headerCondo && headerCondo !== 'todos' && headerCondo !== 'global' ? headerCondo : '');

  const isGlobalTable = GLOBAL_TABLE_WITHOUT_CONDO_ID.has(table);

  if (!isGlobalTable) {
    if (!isValidUuid(candidateCondoId)) {
      return jsonResponse(
        { erro: `Isolamento Multi-Tenant Obrigatório: condominioId UUID válido é obrigatório para "${table}".`, data: [] },
        400
      );
    }
    if (!isCondominioAutorizado(auth.context, candidateCondoId)) {
      return jsonResponse({ erro: 'Acesso negado a este condomínio.', data: [] }, 403);
    }

    const semCondo = filtersList.filter(f => f.field !== 'condominio_id');
    semCondo.push({ field: 'condominio_id', op: 'eq', value: candidateCondoId });
    filtersList.length = 0;
    filtersList.push(...semCondo);
  }

  if (!verificarPermissaoTabelaCache(auth.context, table, isGlobalTable ? undefined : candidateCondoId)) {
    return jsonResponse({ erro: `Sem permissão no módulo correspondente para consultar "${table}".`, data: [] }, 403);
  }

  const cache = createUpstashCache(env);
  const cacheKey = buildTenantCacheKey({
    table,
    condominioId: isGlobalTable ? undefined : candidateCondoId,
    operadorScope: isGlobalTable ? auth.context.operador.id : undefined,
    select,
    filters: filtersList,
    orderBy,
    limit
  });

  const tags = [`table:${table}`];
  if (!isGlobalTable && candidateCondoId) tags.push(`condominio:${candidateCondoId}`);
  if (isGlobalTable) tags.push(`op:${auth.context.operador.id}`);

  if (!forceRefresh) {
    const cached = await cache.get(cacheKey);
    if (cached) {
      try {
        const parsedData = JSON.parse(cached);
        const latencyMs = Date.now() - start;
        return jsonResponse(
          {
            sucesso: true,
            cached: true,
            origem: cache.isConfigured() ? 'upstash-redis' : 'memory',
            latencyMs,
            total: Array.isArray(parsedData) ? parsedData.length : 1,
            data: parsedData
          },
          200,
          { 'X-Cache': 'HIT', 'X-Response-Time': `${latencyMs}ms` }
        );
      } catch {
        // Segue para consulta ao Supabase
      }
    }
  }

  const cfg = getSupabaseServerConfig(env);
  const queryParams = new URLSearchParams();

  // Nunca permite ler colunas sensíveis de operadores caso tabela operadores seja consultada
  let safeSelect = String(select || '*');
  if (table === 'operadores' && safeSelect.trim() === '*') {
    safeSelect = 'id,condominio_id,nome,login,email,auth_user_id,nivel_acesso,nivel_acesso_custom_id,perfil,funcao,cargo,foto_url,acesso_global_condominios,permissoes,unidade,ativo,created_at';
  }
  queryParams.set('select', safeSelect);

  for (const f of filtersList) {
    if (!f?.field || f.value === undefined) continue;
    const op = f.op || 'eq';
    if (op === 'eq') queryParams.append(f.field, `eq.${f.value}`);
    else if (op === 'neq') queryParams.append(f.field, `neq.${f.value}`);
    else if (op === 'in') queryParams.append(f.field, `in.(${Array.isArray(f.value) ? f.value.join(',') : f.value})`);
    else if (op === 'gte') queryParams.append(f.field, `gte.${f.value}`);
    else if (op === 'lte') queryParams.append(f.field, `lte.${f.value}`);
    else if (op === 'ilike') queryParams.append(f.field, `ilike.%${f.value}%`);
  }

  if (orderBy?.field) {
    queryParams.set('order', `${orderBy.field}.${orderBy.ascending ? 'asc' : 'desc'}`);
  }
  if (limit && Number(limit) > 0) {
    queryParams.set('limit', String(Math.min(Number(limit), 2000)));
  }

  const fetchFn = getFetchFn(env);
  const restUrl = `${cfg.url}/rest/v1/${table}?${queryParams.toString()}`;
  const supabaseRes = await fetchFn(restUrl, {
    method: 'GET',
    headers: {
      apikey: cfg.anonKey,
      Authorization: `Bearer ${auth.context.jwt}`,
      'Content-Type': 'application/json'
    }
  });

  if (!supabaseRes.ok) {
    const errText = await supabaseRes.text();
    return jsonResponse({ erro: `Erro no Supabase: ${errText}` }, supabaseRes.status);
  }

  let data = await supabaseRes.json();

  // Filtro adicional de segurança para tabela condominios quando não for Admin Geral explícito
  if (isGlobalTable && Array.isArray(data) && !auth.context.eAdminGlobal) {
    data = data.filter((c: any) => auth.context.allowedCondominioIds.has(String(c?.id || '')));
  }

  const ttlFinal = Number(ttlSeconds) > 0 ? Number(ttlSeconds) : 180;
  await cache.set(cacheKey, JSON.stringify(data), ttlFinal, tags);

  const latencyMs = Date.now() - start;
  return jsonResponse(
    {
      sucesso: true,
      cached: false,
      origem: 'supabase',
      latencyMs,
      total: Array.isArray(data) ? data.length : 1,
      data
    },
    200,
    { 'X-Cache': 'MISS', 'X-Response-Time': `${latencyMs}ms` }
  );
}

export async function handleCacheInvalidate(request: Request, env: RuntimeEnv): Promise<Response> {
  const auth = await authenticateRequest(request, env);
  if (!auth.ok) {
    return jsonResponse({ erro: auth.error }, auth.status);
  }

  const body = await readJsonBody(request);
  const { table, tag, condominioId } = body || {};

  if (condominioId && !isCondominioAutorizado(auth.context, String(condominioId))) {
    return jsonResponse({ erro: 'Não autorizado a invalidar cache deste condomínio.' }, 403);
  }
  if (!condominioId && !auth.context.eAdminGlobal && !table) {
    return jsonResponse({ erro: 'Informe condominioId autorizado para invalidar cache.' }, 400);
  }

  const cache = createUpstashCache(env);
  let removidos = 0;

  if (condominioId) {
    if (table) {
      removidos += await cache.invalidateByPattern(`porttohub:v1:condo:${condominioId}:${table}:*`);
      if (table === 'configuracoes') {
        removidos += await cache.invalidateByPattern(`porttohub:v1:condo:${condominioId}:niveis_acesso:*`);
      }
    } else {
      removidos += await cache.invalidateByTag(`condominio:${condominioId}`);
      removidos += await cache.invalidateByPattern(`porttohub:v1:condo:${condominioId}:*`);
    }
  } else if (auth.context.eAdminGlobal) {
    if (table) {
      removidos += await cache.invalidateByTag(`table:${table}`);
      if (table === 'configuracoes') {
        removidos += await cache.invalidateByTag('table:niveis_acesso');
      }
    }
    if (tag) {
      removidos += await cache.invalidateByTag(String(tag));
    }
  } else if (table) {
    for (const allowedCondo of auth.context.allowedCondominioIds) {
      removidos += await cache.invalidateByPattern(`porttohub:v1:condo:${allowedCondo}:${table}:*`);
      if (table === 'configuracoes') {
        removidos += await cache.invalidateByPattern(`porttohub:v1:condo:${allowedCondo}:niveis_acesso:*`);
      }
    }
  }

  return jsonResponse({
    sucesso: true,
    removidos,
    mensagem: `${removidos} entrada(s) de cache invalidada(s).`
  });
}

export async function handleCacheStats(request: Request, env: RuntimeEnv): Promise<Response> {
  const auth = await authenticateRequest(request, env);
  if (!auth.ok) {
    return jsonResponse({ erro: auth.error }, auth.status);
  }

  const cache = createUpstashCache(env);
  const stats = await cache.getStats();

  return jsonResponse({
    sucesso: true,
    ...stats,
    horarioServidor: new Date().toLocaleTimeString('pt-BR', { timeZone: 'America/Sao_Paulo' })
  });
}

export async function handleCacheClear(request: Request, env: RuntimeEnv): Promise<Response> {
  const auth = await authenticateRequest(request, env);
  if (!auth.ok) {
    return jsonResponse({ erro: auth.error }, auth.status);
  }

  const cache = createUpstashCache(env);
  if (auth.context.eAdminGlobal) {
    await cache.flush();
    return jsonResponse({ sucesso: true, mensagem: 'Cache global limpo com sucesso.' });
  }

  let removidos = 0;
  for (const condoId of auth.context.allowedCondominioIds) {
    removidos += await cache.invalidateByPattern(`porttohub:v1:condo:${condoId}:*`);
  }
  return jsonResponse({
    sucesso: true,
    removidos,
    mensagem: 'Cache dos condomínios autorizados limpo com sucesso.'
  });
}

export async function handleCacheWarmup(request: Request, env: RuntimeEnv): Promise<Response> {
  const start = Date.now();
  const auth = await authenticateRequest(request, env);
  if (!auth.ok) {
    return jsonResponse({ erro: auth.error }, auth.status);
  }

  const body = await readJsonBody(request);
  const condominioId = body?.condominioId ? String(body.condominioId).trim() : '';

  if (!isValidUuid(condominioId) || !isCondominioAutorizado(auth.context, condominioId)) {
    return jsonResponse({ erro: 'Condomínio inválido ou não autorizado para aquecimento de cache.' }, 403);
  }

  const cfg = getSupabaseServerConfig(env);
  const cache = createUpstashCache(env);

  const tabelasParaAquecer = [
    { table: 'chaves', ttl: 180, select: 'id,condominio_id,codigo_chave,nome_chave,status,localizacao' },
    { table: 'moradores', ttl: 300, select: 'id,condominio_id,nome,bloco,unidade,telefone,status_acesso,tag_rfid,veiculo_placa,veiculo_modelo' },
    { table: 'entregadores', ttl: 300, select: '*' },
    { table: 'bancada_volumes', ttl: 60, select: '*' }
  ];

  const fetchFn = getFetchFn(env);
  const resultados: any[] = [];
  for (const item of tabelasParaAquecer) {
    if (!verificarPermissaoTabelaCache(auth.context, item.table, condominioId)) {
      resultados.push({ table: item.table, status: 'negado' });
      continue;
    }
    try {
      const restUrl = `${cfg.url}/rest/v1/${item.table}?select=${encodeURIComponent(item.select)}&condominio_id=eq.${encodeURIComponent(condominioId)}`;
      const resp = await fetchFn(restUrl, {
        headers: {
          apikey: cfg.anonKey,
          Authorization: `Bearer ${auth.context.jwt}`
        }
      });
      if (resp.ok) {
        const dados = await resp.json();
        const key = buildTenantCacheKey({
          table: item.table,
          condominioId,
          select: item.select,
          filters: [{ field: 'condominio_id', op: 'eq', value: condominioId }]
        });
        await cache.set(key, JSON.stringify(dados), item.ttl, [`table:${item.table}`, `condominio:${condominioId}`]);
        resultados.push({ table: item.table, registros: Array.isArray(dados) ? dados.length : 0, status: 'ok' });
      }
    } catch (itemErr: any) {
      resultados.push({ table: item.table, status: 'erro', erro: itemErr?.message || 'Erro' });
    }
  }

  return jsonResponse({
    sucesso: true,
    tempoTotalMs: Date.now() - start,
    tabelasAquecidas: resultados
  });
}

export async function handleCacheBenchmark(request: Request, env: RuntimeEnv): Promise<Response> {
  const auth = await authenticateRequest(request, env);
  if (!auth.ok) {
    return jsonResponse({ erro: auth.error }, auth.status);
  }

  const cfg = getSupabaseServerConfig(env);
  const cache = createUpstashCache(env);

  const fetchFn = getFetchFn(env);
  try {
    const t0 = Date.now();
    const supRes = await fetchFn(`${cfg.url}/rest/v1/condominios?select=id,nome&limit=20`, {
      headers: {
        apikey: cfg.anonKey,
        Authorization: `Bearer ${auth.context.jwt}`
      }
    });
    const supData = await supRes.json();
    const latenciaSupabaseMs = Date.now() - t0;

    const testKey = `porttohub:v1:op:${auth.context.operador.id}:benchmark`;
    await cache.set(testKey, JSON.stringify(supData), 60);

    const t1 = Date.now();
    await cache.get(testKey);
    const latenciaRedisMs = Date.now() - t1;

    const ganhoDesempenho =
      latenciaRedisMs > 0
        ? `${(latenciaSupabaseMs / latenciaRedisMs).toFixed(1)}x mais rápido`
        : 'Instantâneo (< 1ms)';

    return jsonResponse({
      sucesso: true,
      latenciaSupabaseMs,
      latenciaRedisMs: Math.max(latenciaRedisMs, 0.5),
      ganhoDesempenho,
      reducaoLatenciaPercentual: `${(((latenciaSupabaseMs - latenciaRedisMs) / Math.max(latenciaSupabaseMs, 1)) * 100).toFixed(1)}%`,
      itensRetornados: Array.isArray(supData) ? supData.length : 0,
      provider: cache.isConfigured() ? 'upstash-redis-rest' : 'in-memory-fallback'
    });
  } catch (err: any) {
    return jsonResponse({ erro: err?.message || 'Erro ao executar benchmark.' }, 500);
  }
}
