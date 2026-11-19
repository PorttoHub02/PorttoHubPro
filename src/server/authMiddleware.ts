/**
 * Verificação de JWT Supabase e Autorização Multi-Tenant no Servidor (Node & Cloudflare Workers)
 *
 * REGRAS DE SEGURANÇA:
 * - Nunca confia em condominioId, papel ou usuário enviado pelo body/header do cliente.
 * - Valida o Bearer JWT diretamente no Supabase Auth (`/auth/v1/user`).
 * - Resolve o perfil do operador e vínculos explícitos (`operador_condominios`).
 * - Acesso global SOMENTE quando `operador.acesso_global_condominios === true`.
 */

import type { RuntimeEnv } from './upstashClient';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isValidUuid(value?: string | null): boolean {
  return Boolean(value && typeof value === 'string' && UUID_REGEX.test(value.trim()));
}

const URL_PLACEHOLDER_MARKERS = ['SEU_PROJETO', 'configuracao-pendente', 'seu-projeto'];
const KEY_PLACEHOLDER_MARKERS = ['SUA_CHAVE', 'configuracao-pendente', 'sua-chave'];

function isSecretSupabaseKeyValue(value: string): boolean {
  const clean = value.trim();
  if (!clean) return false;
  if (/^sb_secret_/i.test(clean)) return true;

  const parts = clean.split('.');
  if (parts.length === 3 && parts[0].startsWith('eyJ')) {
    try {
      const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
      const jsonStr =
        typeof atob === 'function'
          ? atob(padded)
          : Buffer.from(padded, 'base64').toString('utf8');
      const payload = JSON.parse(jsonStr);
      if (String(payload?.role || '').toLowerCase() === 'service_role') {
        return true;
      }
    } catch {
      // Ignora payload não-JWT
    }
  }
  return false;
}

export function isValidSupabaseUrlValue(raw?: string | null): boolean {
  const clean = String(raw || '').trim();
  if (!clean) return false;
  if (URL_PLACEHOLDER_MARKERS.some(marker => clean.includes(marker))) return false;
  try {
    const parsed = new URL(clean);
    return (parsed.protocol === 'https:' || parsed.protocol === 'http:') && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

export function isValidPublicSupabaseKeyValue(raw?: string | null): boolean {
  const clean = String(raw || '').trim();
  if (!clean || clean.length <= 20) return false;
  if (KEY_PLACEHOLDER_MARKERS.some(marker => clean.includes(marker))) return false;
  if (isSecretSupabaseKeyValue(clean)) return false;
  return true;
}

export interface PublicSupabaseConfig {
  url: string;
  publicKey: string;
  urlSource: 'SUPABASE_URL' | 'VITE_SUPABASE_URL' | null;
  keySource: 'SUPABASE_PUBLISHABLE_KEY' | 'SUPABASE_ANON_KEY' | 'VITE_SUPABASE_ANON_KEY' | null;
  urlPresent: boolean;
  urlValid: boolean;
  keyPresent: boolean;
  publicKeyValid: boolean;
  configured: boolean;
}

export function resolvePublicSupabaseConfig(env: RuntimeEnv): PublicSupabaseConfig {
  const urlCandidates: Array<{ name: 'SUPABASE_URL' | 'VITE_SUPABASE_URL'; value: string }> = [
    { name: 'SUPABASE_URL', value: String(env?.SUPABASE_URL || '').trim() },
    { name: 'VITE_SUPABASE_URL', value: String(env?.VITE_SUPABASE_URL || '').trim() }
  ];

  const keyCandidates: Array<{
    name: 'SUPABASE_PUBLISHABLE_KEY' | 'SUPABASE_ANON_KEY' | 'VITE_SUPABASE_ANON_KEY';
    value: string;
  }> = [
    { name: 'SUPABASE_PUBLISHABLE_KEY', value: String(env?.SUPABASE_PUBLISHABLE_KEY || '').trim() },
    { name: 'SUPABASE_ANON_KEY', value: String(env?.SUPABASE_ANON_KEY || '').trim() },
    { name: 'VITE_SUPABASE_ANON_KEY', value: String(env?.VITE_SUPABASE_ANON_KEY || '').trim() }
  ];

  let url = '';
  let urlSource: PublicSupabaseConfig['urlSource'] = null;
  let urlPresent = false;
  for (const c of urlCandidates) {
    if (c.value && !URL_PLACEHOLDER_MARKERS.some(m => c.value.includes(m))) {
      urlPresent = true;
    }
    if (!url && isValidSupabaseUrlValue(c.value)) {
      url = c.value.replace(/\/+$/, '');
      urlSource = c.name;
    }
  }

  let publicKey = '';
  let keySource: PublicSupabaseConfig['keySource'] = null;
  let keyPresent = false;
  for (const c of keyCandidates) {
    if (c.value && !KEY_PLACEHOLDER_MARKERS.some(m => c.value.includes(m))) {
      keyPresent = true;
    }
    if (!publicKey && isValidPublicSupabaseKeyValue(c.value)) {
      publicKey = c.value;
      keySource = c.name;
    }
  }

  const urlValid = Boolean(url);
  const publicKeyValid = Boolean(publicKey);

  return {
    url,
    publicKey,
    urlSource,
    keySource,
    urlPresent,
    urlValid,
    keyPresent,
    publicKeyValid,
    configured: urlValid && publicKeyValid
  };
}

export function getSupabaseServerConfig(env: RuntimeEnv): {
  url: string;
  anonKey: string;
  serviceRoleKey: string;
  configured: boolean;
} {
  const pub = resolvePublicSupabaseConfig(env);
  const serviceRoleKey = String(env?.SUPABASE_SERVICE_ROLE_KEY || env?.SUPABASE_SECRET_KEY || '').trim();

  return {
    url: pub.url,
    anonKey: pub.publicKey,
    serviceRoleKey,
    configured: pub.configured
  };
}

export type PerfilPadrao = 'admin_geral' | 'admin_condominio' | 'supervisor' | 'operador';

export function normalizarPerfilOperador(operador?: {
  perfil?: string | null;
  nivel_acesso?: number | null;
  acesso_global_condominios?: boolean | null;
  ativo?: boolean | null;
} | null): PerfilPadrao {
  if (!operador) return 'operador';
  const perfil = String(operador.perfil || '').trim().toLowerCase();

  if (
    operador.ativo !== false &&
    operador.acesso_global_condominios === true &&
    perfil === 'admin_geral'
  ) {
    return 'admin_geral';
  }

  if (perfil === 'admin_condominio') {
    return 'admin_condominio';
  }
  if (perfil === 'supervisor') {
    return 'supervisor';
  }
  return 'operador';
}

export interface AuthContext {
  jwt: string;
  authUser: {
    id: string;
    email?: string;
  };
  operador: {
    id: string;
    nome?: string;
    login?: string;
    email?: string;
    perfil?: string;
    nivel_acesso?: number;
    nivel_acesso_custom_id?: string | null;
    permissoes?: Record<string, any> | null;
    condominio_id?: string | null;
    acesso_global_condominios?: boolean;
    ativo?: boolean;
  };
  perfilNormalizado: PerfilPadrao;
  eAdminGlobal: boolean;
  allowedCondominioIds: Set<string>;
  niveisAcessoPorCondo?: Record<string, any[]>;
}

export type AuthResult =
  | { ok: true; context: AuthContext }
  | { ok: false; status: number; error: string };

export async function authenticateRequest(
  request: Request,
  env: RuntimeEnv
): Promise<AuthResult> {
  const cfg = getSupabaseServerConfig(env);
  if (!cfg.configured) {
    return {
      ok: false,
      status: 503,
      error: 'Configuração Supabase ausente no servidor (SUPABASE_URL / SUPABASE_ANON_KEY).'
    };
  }

  const authHeader = request.headers.get('authorization') || request.headers.get('Authorization') || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match || !match[1]) {
    return { ok: false, status: 401, error: 'Token Bearer ausente.' };
  }
  const jwt = match[1].trim();

  const fetchFn: typeof fetch = typeof (env as any)?.__fetchImpl === 'function' ? (env as any).__fetchImpl : fetch;

  // 1. Verifica token no Supabase Auth
  let authUser: any = null;
  try {
    const userResp = await fetchFn(`${cfg.url}/auth/v1/user`, {
      method: 'GET',
      headers: {
        apikey: cfg.anonKey,
        Authorization: `Bearer ${jwt}`
      }
    });
    if (!userResp.ok) {
      return { ok: false, status: 401, error: 'Sessão inválida ou expirada.' };
    }
    authUser = await userResp.json();
  } catch {
    return { ok: false, status: 502, error: 'Falha ao validar token no serviço Supabase Auth.' };
  }

  if (!authUser?.id) {
    return { ok: false, status: 401, error: 'Usuário Auth não identificado.' };
  }

  // 2. Consulta registro do operador vinculado ao authUser.id
  const readKey = cfg.serviceRoleKey || cfg.anonKey;
  const readBearer = cfg.serviceRoleKey || jwt;
  const baseHeaders = {
    apikey: readKey,
    Authorization: `Bearer ${readBearer}`,
    'Content-Type': 'application/json'
  };

  let operador: any = null;
  try {
    const opCols = 'id,nome,login,email,perfil,nivel_acesso,nivel_acesso_custom_id,permissoes,condominio_id,acesso_global_condominios,ativo,auth_user_id';
    const opResp = await fetchFn(
      `${cfg.url}/rest/v1/operadores?select=${opCols}&auth_user_id=eq.${encodeURIComponent(authUser.id)}&limit=1`,
      { headers: baseHeaders }
    );
    if (opResp.ok) {
      const rows: any[] = await opResp.json();
      if (Array.isArray(rows) && rows.length > 0) {
        operador = rows[0];
      }
    }

    if (!operador && authUser.email) {
      const emailResp = await fetchFn(
        `${cfg.url}/rest/v1/operadores?select=${opCols}&email=ilike.${encodeURIComponent(String(authUser.email).trim().toLowerCase())}&limit=1`,
        { headers: baseHeaders }
      );
      if (emailResp.ok) {
        const rows: any[] = await emailResp.json();
        if (Array.isArray(rows) && rows.length > 0) {
          operador = rows[0];
        }
      }
    }
  } catch {
    return { ok: false, status: 502, error: 'Falha ao consultar operador autorizado.' };
  }

  if (!operador) {
    return { ok: false, status: 403, error: 'Conta Auth sem operador vinculado na base.' };
  }

  if (operador.auth_user_id && String(operador.auth_user_id) !== String(authUser.id)) {
    return { ok: false, status: 403, error: 'Vínculo auth_user_id incompatível com a conta autenticada.' };
  }

  if (operador.ativo === false) {
    return { ok: false, status: 403, error: 'Operador desativado.' };
  }

  // Regra estrita e única: acesso global SOMENTE quando ativo !== false, acesso_global_condominios === true e perfil === 'admin_geral'
  const perfilRawOp = String(operador.perfil || '').trim().toLowerCase();
  const eAdminGlobal =
    operador.ativo !== false &&
    operador.acesso_global_condominios === true &&
    perfilRawOp === 'admin_geral';
  const perfilNormalizado = normalizarPerfilOperador(operador);
  const allowedCondominioIds = new Set<string>();

  if (isValidUuid(operador.condominio_id)) {
    allowedCondominioIds.add(String(operador.condominio_id).trim());
  }

  // Carrega vínculos explícitos em operador_condominios (se tabela existir)
  try {
    const linkResp = await fetchFn(
      `${cfg.url}/rest/v1/operador_condominios?select=condominio_id,ativo&operador_id=eq.${encodeURIComponent(operador.id)}`,
      { headers: baseHeaders }
    );
    if (linkResp.ok) {
      const links: any[] = await linkResp.json();
      if (Array.isArray(links)) {
        for (const l of links) {
          if (l.ativo !== false && isValidUuid(l.condominio_id)) {
            allowedCondominioIds.add(String(l.condominio_id).trim());
          }
        }
      }
    }
  } catch {
    // Segue com vínculo principal se tabela ainda não existir durante migração
  }

  // Carrega configuracoes.niveis_acesso dos condomínios autorizados (fonte única no banco)
  const niveisAcessoPorCondo: Record<string, any[]> = {};
  if (!eAdminGlobal && allowedCondominioIds.size > 0) {
    try {
      const idsList = Array.from(allowedCondominioIds).join(',');
      const cfgResp = await fetchFn(
        `${cfg.url}/rest/v1/configuracoes?select=condominio_id,niveis_acesso&condominio_id=in.(${idsList})`,
        { headers: baseHeaders }
      );
      if (cfgResp.ok) {
        const cfgRows: any[] = await cfgResp.json();
        if (Array.isArray(cfgRows)) {
          for (const row of cfgRows) {
            if (isValidUuid(row?.condominio_id) && Array.isArray(row?.niveis_acesso)) {
              niveisAcessoPorCondo[String(row.condominio_id).trim()] = row.niveis_acesso;
            }
          }
        }
      }
    } catch {
      // Segue com matriz padrão quando configuracoes não estiver acessível (ex.: testes mockados)
    }
  }

  return {
    ok: true,
    context: {
      jwt,
      authUser: { id: String(authUser.id), email: authUser.email },
      operador,
      perfilNormalizado,
      eAdminGlobal,
      allowedCondominioIds,
      niveisAcessoPorCondo
    }
  };
}

function ehAdminGlobalContexto(ctx?: AuthContext | null): boolean {
  if (!ctx || !ctx.eAdminGlobal) return false;
  const op = ctx.operador;
  return Boolean(
    op &&
    op.ativo !== false &&
    op.acesso_global_condominios === true &&
    String(op.perfil || '').trim().toLowerCase() === 'admin_geral'
  );
}

export function isCondominioAutorizado(ctx: AuthContext, condominioId?: string | null): boolean {
  if (!condominioId || typeof condominioId !== 'string') return false;
  const clean = condominioId.trim();
  if (!isValidUuid(clean)) return false;
  if (ehAdminGlobalContexto(ctx)) return true;
  return ctx.allowedCondominioIds.has(clean);
}

/**
 * Sincronizado com public.operador_pode_gerenciar_operadores() e operador_pode_gerenciar_operadores(p_condominio_id):
 * - Sem parâmetro: exclusivo de administrador global (perfil = 'admin_geral', acesso_global_condominios === true, ativo).
 * - Com parâmetro: global OU exclusivamente perfil = 'admin_condominio' do próprio condomínio principal.
 * - admin_local, admin, master, supervisor e operador NUNCA recebem poder administrativo de gestão de operadores.
 */
export function podeGerenciarOperadores(ctx: AuthContext, targetCondominioId?: string | null): boolean {
  if (ehAdminGlobalContexto(ctx)) return true;
  if (!targetCondominioId || !isValidUuid(targetCondominioId)) return false;

  if (ctx.operador?.ativo === false) return false;
  const perfilRaw = String(ctx.operador?.perfil || '').trim().toLowerCase();
  if (ctx.perfilNormalizado !== 'admin_condominio' || perfilRaw !== 'admin_condominio') {
    return false;
  }

  const primaryCondo = String(ctx.operador.condominio_id || '').trim();
  return isValidUuid(primaryCondo) && primaryCondo === targetCondominioId.trim();
}

function resolverAliasAcaoBackend(modKey: string, acao: string): string | null {
  if (modKey === 'encomendas') {
    if (['entrada_lote', 'criar_lote', 'triagem', 'baixa', 'cadastrar_entregador'].includes(acao)) return 'criar';
    if (['editar_pacote', 'editar_lotes'].includes(acao)) return 'editar';
    if (['excluir_pacote', 'excluir_lotes'].includes(acao)) return 'excluir';
    if (['dossie', 'historico'].includes(acao)) return 'visualizar';
  }
  if (modKey === 'custodia') {
    if (acao === 'receber') return 'criar';
    if (acao === 'baixa') return 'editar';
    if (acao === 'auditoria') return 'visualizar';
  }
  if (modKey === 'chaves') {
    if (['cadastrar', 'emprestar'].includes(acao)) return 'criar';
    if (acao === 'devolver') return 'editar';
  }
  if (modKey === 'rondas') {
    if (['iniciar_ronda', 'cadastrar_pontos'].includes(acao)) return 'criar';
    if (acao === 'setores') return 'editar';
  }
  if (modKey === 'autorizados') {
    if (['cadastrar', 'dar_entrada'].includes(acao)) return 'criar';
    if (acao === 'dar_saida') return 'editar';
  }
  if (modKey === 'materiais') {
    if (acao === 'cadastrar_equipamentos') return 'criar';
    if (acao === 'alterar_status') return 'editar';
  }
  if (modKey === 'manutencao') {
    if (acao === 'abrir_os') return 'criar';
    if (acao === 'concluir') return 'editar';
  }
  if (modKey === 'ocorrencias' && acao === 'resolver') return 'editar';
  if (modKey === 'passagem_posto') {
    if (acao === 'assumir_posto') return 'criar';
    if (acao === 'relatorio') return 'visualizar';
  }
  if (modKey === 'cadastros') {
    if (['operadores', 'cadastrar_operadores', 'cadastrar_morador'].includes(acao)) return 'criar';
    if (['editar_operadores', 'editar_morador', 'configurar_condominio'].includes(acao)) return 'editar';
    if (['excluir_operadores', 'excluir_morador'].includes(acao)) return 'excluir';
    if (['visualizar_moradores', 'visualizar_operadores', 'exportar_moradores'].includes(acao)) return 'visualizar';
  }
  if (modKey === 'historico_absoluto') {
    if (['ver_feed', 'ver_metricas', 'exportar_csv'].includes(acao)) return 'visualizar';
    if (acao === 'limpar_dados') return 'excluir';
  }
  if (modKey === 'bancada') {
    if (acao === 'lancar') return 'criar';
    if (acao === 'baixa') return 'editar';
    if (acao === 'zerar') return 'excluir';
    if (acao === 'historico') return 'visualizar';
  }
  if (modKey === 'reservas') {
    if (['aprovar', 'gerenciar_areas', 'vistoria'].includes(acao)) return 'editar';
    if (acao === 'cancelar') return 'excluir';
  }
  if (modKey === 'controle_acesso') {
    if (['liberar_entrada', 'gerar_passe_qr'].includes(acao)) return 'criar';
    if (['registrar_saida', 'bloquear', 'configurar_portoes'].includes(acao)) return 'editar';
  }
  return null;
}

function extrairIdNivelBackend(ctx: AuthContext): {
  nivelId: string;
  ehNivelCustom: boolean;
  nivelNum: number;
  perfilRaw: string;
  ehAdminCondoPerfil: boolean;
  ehSupervisorPerfil: boolean;
  ehSindicoPerfil: boolean;
} {
  const perfilRaw = String(ctx.operador.perfil || '').trim().toLowerCase();
  const hasNivel = ctx.operador.nivel_acesso !== undefined && ctx.operador.nivel_acesso !== null;
  const nivelNum = hasNivel ? Number(ctx.operador.nivel_acesso) : 3;
  const customId = String(ctx.operador.nivel_acesso_custom_id || '').trim();
  const customLower = customId.toLowerCase();

  const ehAdminCondoPerfil = ctx.perfilNormalizado === 'admin_condominio';
  const ehSupervisorPerfil = !ehAdminCondoPerfil && ctx.perfilNormalizado === 'supervisor';
  const ehSindicoPerfil = !ehAdminCondoPerfil && !ehSupervisorPerfil && perfilRaw.includes('sind');

  const perfilNivelId = ehAdminCondoPerfil
    ? 'nivel_1'
    : ehSupervisorPerfil
      ? 'nivel_2'
      : ehSindicoPerfil
        ? 'nivel_4'
        : 'nivel_3';

  let nivelId = perfilNivelId;
  let ehNivelCustom = false;

  if (customId) {
    if (['0', '1', 'nivel_0', 'nivel_1'].includes(customLower)) {
      nivelId = perfilNivelId;
      ehNivelCustom = false;
    } else if (['2', 'nivel_2'].includes(customLower) && !ehAdminCondoPerfil && !ehSupervisorPerfil) {
      nivelId = perfilNivelId;
      ehNivelCustom = false;
    } else if (['4', 'nivel_4'].includes(customLower) && !ehAdminCondoPerfil && !ehSupervisorPerfil && !ehSindicoPerfil) {
      nivelId = perfilNivelId;
      ehNivelCustom = false;
    } else if (['nivel_2', 'nivel_3', 'nivel_4'].includes(customLower)) {
      nivelId = customLower;
      ehNivelCustom = false;
    } else {
      nivelId = customId;
      ehNivelCustom = true;
    }
  }

  return { nivelId, ehNivelCustom, nivelNum, perfilRaw, ehAdminCondoPerfil, ehSupervisorPerfil, ehSindicoPerfil };
}

/**
 * Sincronizado com public.operador_tem_permissao_modulo() e src/services/permissoesService.ts.
 * Avalia vínculo multi-tenant, configuracoes.niveis_acesso do condomínio alvo, operadores.permissoes e NIVEIS_PADRAO.
 */
export function temPermissaoModuloBackend(
  ctx: AuthContext,
  modulo: string,
  acao = 'visualizar',
  targetCondominioId?: string | null
): boolean {
  if (!ctx || ctx.operador?.ativo === false) return false;

  if (targetCondominioId && !isCondominioAutorizado(ctx, targetCondominioId)) {
    return false;
  }

  if (ehAdminGlobalContexto(ctx)) return true;

  let modKey = String(modulo || '').trim().toLowerCase();
  const acaoKey = String(acao || 'visualizar').trim().toLowerCase();
  if (!modKey || !acaoKey) return false;

  if (modKey === 'prestadores') modKey = 'autorizados';
  if (modKey === 'passagem') modKey = 'passagem_posto';

  const { nivelId, ehNivelCustom, perfilRaw, ehAdminCondoPerfil, ehSupervisorPerfil, ehSindicoPerfil } = extrairIdNivelBackend(ctx);

  const condoAlvoCheck = (targetCondominioId && isValidUuid(targetCondominioId))
    ? targetCondominioId.trim()
    : String(ctx.operador.condominio_id || '').trim();

  const ehAdminCondo =
    ehAdminCondoPerfil &&
    perfilRaw === 'admin_condominio' &&
    isValidUuid(ctx.operador.condominio_id) &&
    String(ctx.operador.condominio_id).trim() === condoAlvoCheck;
  const ehSupervisor = !ehAdminCondo && ehSupervisorPerfil;
  const ehSindico = !ehAdminCondo && !ehSupervisor && ehSindicoPerfil;

  if (modKey === 'materiais' && (acaoKey === 'excluir' || acaoKey === 'excluir_equipamento')) {
    if (!ehAdminCondo && !ehSupervisor && !ehNivelCustom && (perfilRaw === 'operador' || perfilRaw === 'porteiro' || perfilRaw === '')) {
      return false;
    }
  }

  if (modKey === 'configuracoes') {
    return false;
  }

  if (modKey === 'cadastros') {
    if (acaoKey === 'condominios' || acaoKey === 'gerenciar_niveis') {
      return false;
    }
    if ([
      'operadores', 'cadastrar_operadores', 'editar_operadores',
      'alterar_senha_operador', 'excluir_operadores', 'configurar_condominio'
    ].includes(acaoKey)) {
      const condoCheck = targetCondominioId || ctx.operador.condominio_id;
      if (!ehAdminCondo || !podeGerenciarOperadores(ctx, condoCheck)) {
        return false;
      }
    }
  }

  if (modKey === 'historico_absoluto' && (acaoKey === 'limpar_dados' || acaoKey === 'excluir')) {
    const condoCheck = targetCondominioId || ctx.operador.condominio_id;
    if (!ehAdminCondo || !podeGerenciarOperadores(ctx, condoCheck)) {
      return false;
    }
  }

  const condoLookup = (targetCondominioId && isValidUuid(targetCondominioId))
    ? targetCondominioId.trim()
    : String(ctx.operador.condominio_id || Array.from(ctx.allowedCondominioIds)[0] || '').trim();
  const niveisCondo = condoLookup && ctx.niveisAcessoPorCondo ? ctx.niveisAcessoPorCondo[condoLookup] : undefined;
  const nivelObj = Array.isArray(niveisCondo)
    ? niveisCondo.find((el: any) => el && String(el.id || '') === nivelId)
    : undefined;
  const nivelPerm: Record<string, any> | null =
    nivelObj?.permissoes && typeof nivelObj.permissoes === 'object' ? nivelObj.permissoes : null;

  // Fail-closed: nível personalizado inexistente no condomínio alvo nunca herda permissões padrão
  if (ehNivelCustom && !nivelPerm) {
    return false;
  }

  const perm: Record<string, any> =
    ctx.operador.permissoes && typeof ctx.operador.permissoes === 'object' ? ctx.operador.permissoes : {};

  if (ehSindico) {
    const resolverModSindico = (src: Record<string, any> | null | undefined) => {
      if (!src || typeof src !== 'object') return undefined;
      return (
        src[modKey] ||
        (modKey === 'autorizados' ? src.prestadores : undefined) ||
        (modKey === 'passagem_posto' ? src.passagem : undefined) ||
        (modKey === 'moradores' ? src.moradores || src.cadastros : undefined)
      );
    };
    const modCfg = resolverModSindico(perm) || resolverModSindico(nivelPerm);

    if (modCfg && typeof modCfg === 'object' && modCfg.visualizar === false) {
      return false;
    }
    if (modKey === 'ocorrencias') {
      return acaoKey === 'visualizar' || acaoKey === 'criar' || acaoKey === 'resolver';
    }
    if ([
      'visualizar',
      'relatorio',
      'dossie',
      'historico',
      'ver_feed',
      'ver_metricas',
      'exportar_csv',
      'visualizar_moradores',
      'visualizar_operadores',
      'auditoria'
    ].includes(acaoKey)) {
      if (modCfg && typeof modCfg === 'object' && modCfg.visualizar !== undefined) {
        return Boolean(modCfg.visualizar);
      }
      return true;
    }
    return false;
  }

  let modDefinidoNoNivel = false;
  const fontes = [perm, nivelPerm];

  for (let passo = 0; passo < fontes.length; passo++) {
    const fonte = fontes[passo];
    if (!fonte || typeof fonte !== 'object') continue;

    if (modKey === 'moradores') {
      const modObj = fonte.moradores;
      const cadObj = fonte.cadastros;

      if (passo === 1 && ((modObj && typeof modObj === 'object') || (cadObj && typeof cadObj === 'object'))) {
        modDefinidoNoNivel = true;
      }

      if (modObj && typeof modObj === 'object') {
        if (modObj.visualizar === false) return false;
        if (acaoKey === 'visualizar' && modObj.visualizar !== undefined) return Boolean(modObj.visualizar);
        if (modObj[acaoKey] !== undefined) return Boolean(modObj[acaoKey]);
        if (['adicionar', 'cadastrar', 'criar'].includes(acaoKey)) {
          const val = modObj.adicionar ?? modObj.criar ?? modObj.cadastrar;
          if (val !== undefined) return Boolean(val);
        }
      }

      if (cadObj && typeof cadObj === 'object') {
        if (cadObj.visualizar === false && cadObj.visualizar_moradores !== true) return false;
        if (acaoKey === 'visualizar' && cadObj.visualizar_moradores !== undefined) return Boolean(cadObj.visualizar_moradores);
        if (['criar', 'adicionar', 'cadastrar'].includes(acaoKey) && (cadObj.cadastrar_morador !== undefined || cadObj.moradores !== undefined)) {
          return Boolean(cadObj.cadastrar_morador ?? cadObj.moradores);
        }
        if (acaoKey === 'editar' && (cadObj.editar_morador !== undefined || cadObj.moradores !== undefined)) {
          return Boolean(cadObj.editar_morador ?? cadObj.moradores);
        }
        if (acaoKey === 'excluir' && cadObj.excluir_morador !== undefined) {
          return Boolean(cadObj.excluir_morador);
        }
      }
    } else {
      const modObj =
        fonte[modKey] ||
        (modKey === 'autorizados' ? fonte.prestadores : undefined) ||
        (modKey === 'passagem_posto' ? fonte.passagem : undefined);

      if (modObj && typeof modObj === 'object') {
        if (passo === 1) {
          modDefinidoNoNivel = true;
        }
        if (modObj.visualizar === false) {
          if (!(modKey === 'cadastros' && ['visualizar_moradores', 'cadastrar_morador', 'gerenciar_veiculos'].includes(acaoKey))) {
            return false;
          }
        }
        if (acaoKey === 'visualizar' && modObj.visualizar !== undefined) {
          return Boolean(modObj.visualizar);
        }
        if (modObj[acaoKey] !== undefined) {
          return Boolean(modObj[acaoKey]);
        }
        const fallbackAcao = resolverAliasAcaoBackend(modKey, acaoKey);
        if (fallbackAcao && modObj[fallbackAcao] !== undefined) {
          return Boolean(modObj[fallbackAcao]);
        }
      }
    }
  }

  if (ehNivelCustom || modDefinidoNoNivel) {
    return false;
  }

  // Matriz padrão oficial (espelha NIVEIS_PADRAO e public.operador_tem_permissao_modulo)
  if (ehAdminCondo) {
    if (modKey === 'historico_absoluto') {
      return ['visualizar', 'ver_feed', 'ver_metricas', 'exportar_csv'].includes(acaoKey);
    }
    if (modKey === 'cadastros') {
      if (['excluir', 'excluir_morador', 'excluir_operadores', 'condominios', 'gerenciar_niveis'].includes(acaoKey)) {
        return false;
      }
      return [
        'visualizar', 'criar', 'editar', 'moradores', 'visualizar_moradores', 'cadastrar_morador',
        'editar_morador', 'gerenciar_veiculos', 'vincular_tags', 'status_acesso_morador', 'exportar_moradores',
        'visualizar_operadores', 'operadores', 'cadastrar_operadores', 'editar_operadores',
        'alterar_senha_operador', 'configurar_condominio'
      ].includes(acaoKey);
    }
    if (modKey === 'bancada') return acaoKey !== 'excluir';
    if (modKey === 'reservas') return acaoKey !== 'excluir';
    if (['excluir', 'excluir_pacote', 'excluir_lotes'].includes(acaoKey)) {
      return modKey === 'encomendas';
    }
    return true;
  }

  if (ehSupervisor) {
    if (modKey === 'historico_absoluto') {
      return ['visualizar', 'ver_feed', 'ver_metricas'].includes(acaoKey);
    }
    if (modKey === 'custodia' && ['editar', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'rondas' && ['setores', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'bancada' && ['zerar', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'reservas' && ['gerenciar_areas', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'controle_acesso' && ['configurar_portoes', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'cadastros') {
      return [
        'visualizar', 'criar', 'editar', 'moradores', 'visualizar_moradores', 'cadastrar_morador',
        'editar_morador', 'gerenciar_veiculos', 'vincular_tags', 'status_acesso_morador',
        'exportar_moradores', 'visualizar_operadores'
      ].includes(acaoKey);
    }
    if (['excluir', 'excluir_pacote', 'excluir_lotes'].includes(acaoKey)) {
      return modKey === 'encomendas';
    }
    return true;
  }

  // Perfil Operador / Porteiro (Nível 3)
  switch (modKey) {
    case 'encomendas':
      return ['visualizar', 'criar', 'entrada_lote', 'criar_lote', 'cadastrar_entregador', 'triagem', 'baixa', 'historico'].includes(acaoKey);
    case 'custodia':
      return ['visualizar', 'criar', 'receber', 'baixa'].includes(acaoKey);
    case 'chaves':
      return ['visualizar', 'criar', 'emprestar', 'devolver'].includes(acaoKey);
    case 'rondas':
      return ['visualizar', 'criar', 'iniciar_ronda'].includes(acaoKey);
    case 'autorizados':
      return ['visualizar', 'criar', 'cadastrar', 'dar_entrada', 'dar_saida'].includes(acaoKey);
    case 'materiais':
      return ['visualizar', 'alterar_status'].includes(acaoKey);
    case 'manutencao':
      return ['visualizar', 'criar', 'abrir_os'].includes(acaoKey);
    case 'ocorrencias':
      return ['visualizar', 'criar'].includes(acaoKey);
    case 'passagem_posto':
      return ['visualizar', 'criar', 'editar', 'assumir_posto', 'relatorio'].includes(acaoKey);
    case 'cadastros':
      return ['visualizar_moradores', 'cadastrar_morador', 'gerenciar_veiculos'].includes(acaoKey);
    case 'moradores':
      return ['visualizar', 'criar', 'adicionar', 'cadastrar'].includes(acaoKey);
    case 'historico_absoluto':
      return ['visualizar', 'ver_feed'].includes(acaoKey);
    case 'bancada':
      return ['visualizar', 'criar', 'lancar', 'baixa'].includes(acaoKey);
    case 'reservas':
      return ['visualizar', 'criar', 'vistoria'].includes(acaoKey);
    case 'controle_acesso':
      return ['visualizar', 'criar', 'editar', 'liberar_entrada', 'registrar_saida', 'gerar_passe_qr'].includes(acaoKey);
    default:
      return false;
  }
}

