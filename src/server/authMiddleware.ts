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

export function getSupabaseServerConfig(env: RuntimeEnv): {
  url: string;
  anonKey: string;
  serviceRoleKey: string;
  configured: boolean;
} {
  const url = String(env.SUPABASE_URL || env.VITE_SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const anonKey = String(env.SUPABASE_ANON_KEY || env.VITE_SUPABASE_ANON_KEY || '').trim();
  const serviceRoleKey = String(env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

  return {
    url,
    anonKey,
    serviceRoleKey,
    configured: Boolean(url && anonKey && url.startsWith('http'))
  };
}

export type PerfilPadrao = 'admin_geral' | 'admin_condominio' | 'supervisor' | 'operador';

export function normalizarPerfilOperador(operador?: {
  perfil?: string | null;
  nivel_acesso?: number | null;
  acesso_global_condominios?: boolean | null;
} | null): PerfilPadrao {
  if (!operador) return 'operador';
  if (operador.acesso_global_condominios === true) return 'admin_geral';

  const perfil = String(operador.perfil || '').trim().toLowerCase();
  if (perfil === 'admin_condominio' || perfil === 'admin_local' || perfil === 'admin' || perfil === 'master') {
    return 'admin_condominio';
  }
  if (perfil === 'supervisor' || Number(operador.nivel_acesso) === 2) {
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

  // Regra estrita: acesso global SOMENTE quando acesso_global_condominios === true
  const eAdminGlobal = operador.acesso_global_condominios === true;
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

  return {
    ok: true,
    context: {
      jwt,
      authUser: { id: String(authUser.id), email: authUser.email },
      operador,
      perfilNormalizado,
      eAdminGlobal,
      allowedCondominioIds
    }
  };
}

export function isCondominioAutorizado(ctx: AuthContext, condominioId?: string | null): boolean {
  if (!condominioId || typeof condominioId !== 'string') return false;
  const clean = condominioId.trim();
  if (!isValidUuid(clean)) return false;
  if (ctx.eAdminGlobal) return true;
  return ctx.allowedCondominioIds.has(clean);
}

/**
 * Sincronizado com public.operador_pode_gerenciar_operadores() e operador_pode_gerenciar_operadores(p_condominio_id):
 * - Sem parâmetro: exclusivo de administrador global (acesso_global_condominios === true).
 * - Com parâmetro: global OU admin_condominio do próprio condomínio principal.
 * - Supervisor e operador NUNCA recebem poder administrativo de gestão de operadores automaticamente.
 */
export function podeGerenciarOperadores(ctx: AuthContext, targetCondominioId?: string | null): boolean {
  if (ctx.eAdminGlobal) return true;
  if (!targetCondominioId || !isValidUuid(targetCondominioId)) return false;

  if (ctx.perfilNormalizado !== 'admin_condominio') {
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

/**
 * Sincronizado com public.operador_tem_permissao_modulo() e src/services/permissoesService.ts.
 * Avalia vínculo multi-tenant, regras rígidas de perfil, operadores.permissoes e matriz oficial padrão.
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

  if (ctx.eAdminGlobal) return true;

  let modKey = String(modulo || '').trim().toLowerCase();
  const acaoKey = String(acao || 'visualizar').trim().toLowerCase();
  if (!modKey || !acaoKey) return false;

  if (modKey === 'prestadores') modKey = 'autorizados';
  if (modKey === 'passagem') modKey = 'passagem_posto';

  const perfilRaw = String(ctx.operador.perfil || '').trim().toLowerCase();
  const nivelNum = ctx.operador.nivel_acesso !== undefined && ctx.operador.nivel_acesso !== null
    ? Number(ctx.operador.nivel_acesso)
    : 3;

  const ehAdminCondo = ctx.perfilNormalizado === 'admin_condominio';
  const ehSupervisor = !ehAdminCondo && ctx.perfilNormalizado === 'supervisor';
  const ehSindico = !ehAdminCondo && !ehSupervisor && (perfilRaw.includes('sind') || nivelNum === 4);

  if (modKey === 'materiais' && (acaoKey === 'excluir' || acaoKey === 'excluir_equipamento')) {
    if (!ehAdminCondo && !ehSupervisor && (nivelNum >= 3 || perfilRaw === 'operador' || perfilRaw === 'porteiro')) {
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
    if (['operadores', 'cadastrar_operadores', 'editar_operadores', 'alterar_senha_operador', 'excluir_operadores'].includes(acaoKey)) {
      const condoCheck = targetCondominioId || ctx.operador.condominio_id;
      if (!podeGerenciarOperadores(ctx, condoCheck)) {
        return false;
      }
    }
  }

  const perm: Record<string, any> =
    ctx.operador.permissoes && typeof ctx.operador.permissoes === 'object' ? ctx.operador.permissoes : {};

  if (ehSindico) {
    const modCfg =
      perm[modKey] ||
      (modKey === 'autorizados' ? perm.prestadores : undefined) ||
      (modKey === 'passagem_posto' ? perm.passagem : undefined) ||
      (modKey === 'moradores' ? perm.moradores || perm.cadastros : undefined);

    if (modCfg && typeof modCfg === 'object' && modCfg.visualizar === false) {
      return false;
    }
    if (modKey === 'ocorrencias') {
      return acaoKey === 'visualizar' || acaoKey === 'criar' || acaoKey === 'resolver';
    }
    return [
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
    ].includes(acaoKey);
  }

  if (modKey === 'moradores') {
    const modObj = perm.moradores;
    const cadObj = perm.cadastros;

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
      if (cadObj.visualizar === false) return false;
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
      perm[modKey] ||
      (modKey === 'autorizados' ? perm.prestadores : undefined) ||
      (modKey === 'passagem_posto' ? perm.passagem : undefined);

    if (modObj && typeof modObj === 'object') {
      if (modObj.visualizar === false) return false;
      if (acaoKey === 'visualizar') {
        return modObj.visualizar !== undefined ? Boolean(modObj.visualizar) : true;
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

  // Matriz padrão oficial (espelha NIVEIS_PADRAO e operador_tem_permissao_modulo)
  if (['visualizar', 'historico', 'relatorio', 'ver_feed', 'auditoria', 'visualizar_moradores'].includes(acaoKey)) {
    if (modKey === 'encomendas' && acaoKey === 'dossie' && !ehAdminCondo && !ehSupervisor) {
      return false;
    }
    return true;
  }

  if (ehAdminCondo) {
    if (modKey === 'historico_absoluto') return false;
    if (modKey === 'cadastros' && ['excluir', 'excluir_morador', 'excluir_operadores', 'condominios', 'gerenciar_niveis'].includes(acaoKey)) {
      return false;
    }
    if (modKey === 'reservas' && acaoKey === 'cancelar') return true;
    if (['excluir', 'excluir_pacote', 'excluir_lotes'].includes(acaoKey)) {
      return modKey === 'encomendas';
    }
    return true;
  }

  if (ehSupervisor) {
    if (modKey === 'historico_absoluto') return false;
    if (modKey === 'custodia' && ['editar', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'rondas' && ['setores', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'bancada' && ['zerar', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'reservas' && ['gerenciar_areas', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'controle_acesso' && ['configurar_portoes', 'excluir'].includes(acaoKey)) return false;
    if (modKey === 'cadastros') {
      return [
        'visualizar_moradores', 'cadastrar_morador', 'editar_morador', 'gerenciar_veiculos',
        'vincular_tags', 'status_acesso_morador', 'exportar_moradores', 'visualizar_operadores', 'criar', 'editar'
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
      return ['criar', 'entrada_lote', 'criar_lote', 'cadastrar_entregador', 'triagem', 'baixa', 'historico'].includes(acaoKey);
    case 'custodia':
      return ['criar', 'receber', 'baixa'].includes(acaoKey);
    case 'chaves':
      return ['criar', 'emprestar', 'devolver'].includes(acaoKey);
    case 'rondas':
      return ['criar', 'iniciar_ronda'].includes(acaoKey);
    case 'autorizados':
      return ['criar', 'cadastrar', 'dar_entrada', 'dar_saida'].includes(acaoKey);
    case 'materiais':
      return acaoKey === 'alterar_status';
    case 'manutencao':
      return ['criar', 'abrir_os'].includes(acaoKey);
    case 'ocorrencias':
      return acaoKey === 'criar';
    case 'passagem_posto':
      return ['criar', 'editar', 'assumir_posto'].includes(acaoKey);
    case 'cadastros':
      return ['visualizar_moradores', 'cadastrar_morador', 'gerenciar_veiculos'].includes(acaoKey);
    case 'moradores':
      return ['criar', 'adicionar', 'cadastrar'].includes(acaoKey);
    case 'bancada':
      return ['criar', 'lancar', 'baixa'].includes(acaoKey);
    case 'reservas':
      return ['criar', 'vistoria'].includes(acaoKey);
    case 'controle_acesso':
      return ['criar', 'editar', 'liberar_entrada', 'registrar_saida', 'gerar_passe_qr'].includes(acaoKey);
    default:
      return false;
  }
}

