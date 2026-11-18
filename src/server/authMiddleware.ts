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
    const opCols = 'id,nome,login,email,perfil,nivel_acesso,condominio_id,acesso_global_condominios,ativo,auth_user_id';
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
