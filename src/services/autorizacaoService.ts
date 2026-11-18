import { createClient } from '@supabase/supabase-js';
import {
  supabase,
  obterSupabaseUrl,
  obterSupabaseKey,
  formatarErroDetalhadoSupabase
} from './supabase';

export const OPERADOR_SAFE_COLUMNS =
  'id,condominio_id,auth_user_id,nome,login,email,funcao,cargo,perfil,telefone,unidade,turno,turno_padrao,nivel_acesso,nivel_acesso_custom_id,permissoes,foto_url,acesso_global_condominios,exigir_troca_senha,migrado_auth_em,ativo,created_at,updated_at';

export interface CondominioResumo {
  id: string;
  nome: string;
  [key: string]: any;
}

export type PerfilPadrao = 'admin_geral' | 'admin_condominio' | 'supervisor' | 'operador';

export interface ContextoCondominiosResolvido {
  bloqueado: boolean;
  motivoBloqueio?: string;
  eAdminGeral: boolean;
  eAdminCondominio: boolean;
  eSupervisor: boolean;
  eSindico: boolean;
  ePorteiro: boolean;
  podeTrocarCondominio: boolean;
  mostrarSeletor: boolean;
  condominiosPermitidos: CondominioResumo[];
  condominioInicialId: string;
}

export function isCondominioIdValido(id?: string | null): boolean {
  if (!id || typeof id !== 'string') return false;
  const limpo = id.trim();
  if (!limpo) return false;
  const lower = limpo.toLowerCase();
  if (lower === 'todos' || lower === 'global' || lower === 'null' || lower === 'undefined') {
    return false;
  }
  return true;
}

/**
 * Regra C: Administrador Geral SOMENTE com flag explícito de banco/backend.
 * NUNCA concede acesso global por login === 'admin', 'master', nivel_acesso <= 1
 * ou condominio_id vazio / 'todos' / 'global'.
 */
export function temAcessoGlobalExplicito(operador?: any | null): boolean {
  return Boolean(operador && operador.acesso_global_condominios === true);
}

/**
 * Normaliza perfis legados para o padrão oficial do banco:
 * admin_geral | admin_condominio | supervisor | operador
 * Regra estrita: sem `acesso_global_condominios = true`, NENHUM perfil vira `admin_geral`.
 */
export function normalizarPerfilOperador(operador?: any | null): PerfilPadrao {
  if (temAcessoGlobalExplicito(operador)) {
    return 'admin_geral';
  }
  if (!operador) return 'operador';

  const perfil = String(operador.perfil || '').trim().toLowerCase();
  const nivel =
    operador.nivel_acesso !== undefined && operador.nivel_acesso !== null
      ? Number(operador.nivel_acesso)
      : NaN;

  if (
    perfil === 'admin_condominio' ||
    perfil === 'admin_local' ||
    perfil === 'admin' ||
    perfil === 'master' ||
    nivel === 1
  ) {
    return 'admin_condominio';
  }
  if (perfil === 'supervisor' || nivel === 2) {
    return 'supervisor';
  }
  return 'operador';
}

export function ehAdminCondominio(operador?: any | null): boolean {
  return !temAcessoGlobalExplicito(operador) && normalizarPerfilOperador(operador) === 'admin_condominio';
}

/**
 * Espelha exatamente `operador_pode_gerenciar_operadores()` (0 args = global only)
 * e `operador_pode_gerenciar_operadores(condominio_id)` (global ou `admin_condominio` no seu condomínio principal).
 * Supervisor NÃO possui poder administrativo sobre operadores.
 */
export function podeGerenciarOperadoresNoCondominio(
  operador?: any | null,
  condominioAlvoId?: string | null
): boolean {
  if (!operador) return false;
  if (temAcessoGlobalExplicito(operador)) return true;

  if (!condominioAlvoId) {
    return false;
  }

  if (!ehAdminCondominio(operador)) {
    return false;
  }

  const principalOp = isCondominioIdValido(operador.condominio_id)
    ? String(operador.condominio_id).trim()
    : '';
  const alvo = isCondominioIdValido(condominioAlvoId) ? String(condominioAlvoId).trim() : '';

  return Boolean(principalOp && alvo && principalOp === alvo);
}

export function ehPerfilSupervisor(operador?: any | null): boolean {
  if (!operador || temAcessoGlobalExplicito(operador) || ehAdminCondominio(operador)) return false;
  const perfil = String(operador.perfil || '').toLowerCase();
  const funcao = String(operador.funcao || operador.cargo || '').toLowerCase();
  return (
    Number(operador.nivel_acesso) === 2 ||
    perfil === 'supervisor' ||
    funcao.includes('supervisor')
  );
}

export function ehPerfilSindico(operador?: any | null): boolean {
  if (!operador) return false;
  const perfil = String(operador.perfil || '').toLowerCase();
  const funcao = String(operador.funcao || operador.cargo || '').toLowerCase();
  const nivelCustom = String(operador.nivel_acesso_custom_id || '').toLowerCase();
  return (
    Number(operador.nivel_acesso) === 4 ||
    nivelCustom === 'nivel_4' ||
    perfil === 'sindico' ||
    perfil === 'síndico' ||
    funcao.includes('síndic') ||
    funcao.includes('sindic')
  );
}

export function ehPerfilPorteiroOuComum(operador?: any | null): boolean {
  if (
    !operador ||
    temAcessoGlobalExplicito(operador) ||
    ehAdminCondominio(operador) ||
    ehPerfilSupervisor(operador) ||
    ehPerfilSindico(operador)
  ) {
    return false;
  }
  const perfil = String(operador.perfil || '').toLowerCase();
  const nivel = operador.nivel_acesso !== undefined && operador.nivel_acesso !== null ? Number(operador.nivel_acesso) : 3;
  // Nível 3+ ou perfil porteiro/operador/custom sem flag global são operadores comuns
  if (perfil === 'operador' || perfil === 'porteiro' || nivel >= 3) {
    return true;
  }
  return false;
}

/**
 * Busca os vínculos explícitos na tabela public.operador_condominios.
 * Retorna também se a tabela existe no banco (tabelaDisponivel).
 */
export async function buscarVinculosCondominiosOperador(operadorId: string): Promise<{
  ids: string[];
  tabelaDisponivel: boolean;
  erro?: any;
}> {
  if (!operadorId) return { ids: [], tabelaDisponivel: true };

  try {
    const { data, error } = await supabase
      .from('operador_condominios')
      .select('condominio_id, principal, ativo')
      .eq('operador_id', operadorId);

    if (error) {
      const msg = (error.message || '').toLowerCase();
      const tabelaAusente =
        (error as any).code === '42P01' ||
        (error as any).code === 'PGRST205' ||
        msg.includes('does not exist') ||
        msg.includes('schema cache');

      if (tabelaAusente) {
        return { ids: [], tabelaDisponivel: false };
      }
      console.error('[PorttoHub][Autorização] Erro ao consultar operador_condominios:', error);
      return { ids: [], tabelaDisponivel: true, erro: error };
    }

    const ids = Array.from(
      new Set(
        (data || [])
          .filter((row: any) => row.ativo !== false && isCondominioIdValido(row.condominio_id))
          .map((row: any) => String(row.condominio_id).trim())
      )
    );

    return { ids, tabelaDisponivel: true };
  } catch (err) {
    console.error('[PorttoHub][Autorização] Exceção ao consultar operador_condominios:', err);
    return { ids: [], tabelaDisponivel: false, erro: err };
  }
}

/**
 * Resolve de forma determinística e testável o contexto multi-condomínio de um operador
 * seguindo estritamente as Regras A, B, C e D.
 */
export function resolverContextoCondominiosOperador(params: {
  operador: any;
  condominiosDisponiveis: CondominioResumo[];
  vinculosExplicitosIds?: string[];
  tabelaVinculosDisponivel?: boolean;
  condominioPreferidoId?: string | null;
}): ContextoCondominiosResolvido {
  const {
    operador,
    condominiosDisponiveis,
    vinculosExplicitosIds = [],
    tabelaVinculosDisponivel = true,
    condominioPreferidoId
  } = params;

  const todosValidos = (condominiosDisponiveis || []).filter(c => isCondominioIdValido(c?.id));
  const eAdminGeral = temAcessoGlobalExplicito(operador);
  const eAdminCondominio = ehAdminCondominio(operador);
  const eSupervisor = ehPerfilSupervisor(operador);
  const eSindico = ehPerfilSindico(operador);
  const ePorteiro = ehPerfilPorteiroOuComum(operador);

  // REGRA C: Administrador Geral explícito
  if (eAdminGeral) {
    const preferido = isCondominioIdValido(condominioPreferidoId) && todosValidos.some(c => c.id === condominioPreferidoId)
      ? String(condominioPreferidoId)
      : '';
    const principalOp = isCondominioIdValido(operador?.condominio_id) && todosValidos.some(c => c.id === operador.condominio_id)
      ? String(operador.condominio_id)
      : '';
    const condominioInicialId = preferido || principalOp || todosValidos[0]?.id || '';

    return {
      bloqueado: false,
      eAdminGeral: true,
      eAdminCondominio: false,
      eSupervisor: false,
      eSindico: false,
      ePorteiro: false,
      podeTrocarCondominio: todosValidos.length >= 1,
      mostrarSeletor: todosValidos.length > 0,
      condominiosPermitidos: todosValidos,
      condominioInicialId
    };
  }

  // REGRA B: Supervisor — estritamente pelos vínculos explícitos em operador_condominios
  if (eSupervisor) {
    const setIds = new Set(
      (vinculosExplicitosIds || []).filter(id => isCondominioIdValido(id))
    );

    // Somente na janela de transição antes da criação da tabela operador_condominios
    // aceita o condominio_id unitário já cadastrado (nunca 'todos'/'global').
    if (!tabelaVinculosDisponivel && setIds.size === 0 && isCondominioIdValido(operador?.condominio_id)) {
      setIds.add(String(operador.condominio_id).trim());
    }

    const permitidos = todosValidos.filter(c => setIds.has(c.id));

    if (permitidos.length === 0) {
      return {
        bloqueado: true,
        motivoBloqueio: 'Sua conta de supervisão não possui nenhum condomínio autorizado vinculado. Solicite ao administrador geral o vínculo em Cadastros.',
        eAdminGeral: false,
        eAdminCondominio: false,
        eSupervisor: true,
        eSindico: false,
        ePorteiro: false,
        podeTrocarCondominio: false,
        mostrarSeletor: false,
        condominiosPermitidos: [],
        condominioInicialId: ''
      };
    }

    if (permitidos.length === 1) {
      return {
        bloqueado: false,
        eAdminGeral: false,
        eAdminCondominio: false,
        eSupervisor: true,
        eSindico: false,
        ePorteiro: false,
        podeTrocarCondominio: false,
        mostrarSeletor: false,
        condominiosPermitidos: permitidos,
        condominioInicialId: permitidos[0].id
      };
    }

    const preferido = isCondominioIdValido(condominioPreferidoId) && permitidos.some(c => c.id === condominioPreferidoId)
      ? String(condominioPreferidoId)
      : '';
    const principal = isCondominioIdValido(operador?.condominio_id) && permitidos.some(c => c.id === operador.condominio_id)
      ? String(operador.condominio_id)
      : '';

    return {
      bloqueado: false,
      eAdminGeral: false,
      eAdminCondominio: false,
      eSupervisor: true,
      eSindico: false,
      ePorteiro: false,
      podeTrocarCondominio: true,
      mostrarSeletor: true,
      condominiosPermitidos: permitidos,
      condominioInicialId: preferido || principal || permitidos[0].id
    };
  }

  // REGRAS A e D: Porteiro, Síndico, Admin de Condomínio, Custom RBAC (sem acesso_global_condominios)
  const idPrincipal = isCondominioIdValido(operador?.condominio_id) ? String(operador.condominio_id).trim() : '';
  const idsLinksValidos = (vinculosExplicitosIds || []).filter(id => isCondominioIdValido(id));

  // Porteiro e Síndico padrão sempre ficam restritos a 1 condomínio
  const idPrincipalMatch = todosValidos.find(c => c.id === idPrincipal);
  const linksPermitidos = todosValidos.filter(c => idsLinksValidos.includes(c.id));

  let permitidos: CondominioResumo[] = [];
  if (ePorteiro || eSindico) {
    if (idPrincipalMatch) {
      permitidos = [idPrincipalMatch];
    } else if (linksPermitidos.length === 1) {
      permitidos = [linksPermitidos[0]];
    } else if (!ePorteiro && linksPermitidos.length > 0) {
      permitidos = linksPermitidos;
    }
  } else {
    // admin_condominio / Custom RBAC sem acesso global explícito:
    // Usa o seu condomínio principal ou os vínculos explícitos (nunca todos os condomínios)
    const mapa = new Map<string, CondominioResumo>();
    if (idPrincipalMatch) mapa.set(idPrincipalMatch.id, idPrincipalMatch);
    for (const c of linksPermitidos) {
      mapa.set(c.id, c);
    }
    permitidos = Array.from(mapa.values());
  }

  if (permitidos.length === 0) {
    return {
      bloqueado: true,
      motivoBloqueio: 'Sua conta não possui nenhum condomínio válido vinculado. Solicite ao administrador do sistema.',
      eAdminGeral: false,
      eAdminCondominio,
      eSupervisor: false,
      eSindico,
      ePorteiro,
      podeTrocarCondominio: false,
      mostrarSeletor: false,
      condominiosPermitidos: [],
      condominioInicialId: ''
    };
  }

  const podeAlternarEntreVinculados = !ePorteiro && !eSindico && !eAdminCondominio && permitidos.length >= 2;
  const preferido = podeAlternarEntreVinculados && isCondominioIdValido(condominioPreferidoId) && permitidos.some(c => c.id === condominioPreferidoId)
    ? String(condominioPreferidoId)
    : '';

  return {
    bloqueado: false,
    eAdminGeral: false,
    eAdminCondominio,
    eSupervisor: false,
    eSindico,
    ePorteiro,
    podeTrocarCondominio: podeAlternarEntreVinculados,
    mostrarSeletor: podeAlternarEntreVinculados,
    condominiosPermitidos: permitidos,
    condominioInicialId: preferido || permitidos[0].id
  };
}

/**
 * Reautentica um operador entrante via Supabase Auth usando um cliente efêmero sem persistência
 * (persistSession: false), garantindo que a sessão principal do operador atual não seja
 * substituída indevidamente nem armazene tokens/senhas em localStorage.
 */
export async function verificarCredenciaisOperadorSupabaseAuth(params: {
  email: string;
  password: string;
  expectedAuthUserId?: string | null;
  authVerifier?: (email: string, password: string) => Promise<{ userId: string | null; error?: any }>;
}): Promise<{ ok: boolean; authUserId?: string; error?: string }> {
  const emailLimpo = String(params.email || '').trim().toLowerCase();
  const senhaLimpa = String(params.password || '');

  if (!emailLimpo || !emailLimpo.includes('@')) {
    return {
      ok: false,
      error: 'Operador entrante sem e-mail válido vinculado ao Supabase Auth. Solicite ao administrador configurar o acesso em Cadastros.'
    };
  }
  if (!senhaLimpa) {
    return { ok: false, error: 'Informe a senha de acesso do operador entrante.' };
  }

  try {
    let userId: string | null = null;

    if (params.authVerifier) {
      const customRes = await params.authVerifier(emailLimpo, senhaLimpa);
      if (customRes.error || !customRes.userId) {
        return {
          ok: false,
          error: customRes.error
            ? formatarErroDetalhadoSupabase(customRes.error, 'Reautenticação Supabase Auth')
            : 'Credenciais inválidas no Supabase Auth.'
        };
      }
      userId = customRes.userId;
    } else {
      const url = obterSupabaseUrl();
      const anonKey = obterSupabaseKey();
      if (!url || !anonKey) {
        return { ok: false, error: 'Configuração Supabase ausente no ambiente.' };
      }

      const memoryStorage = {
        getItem: (_key: string) => null,
        setItem: (_key: string, _value: string) => {},
        removeItem: (_key: string) => {}
      };

      const ephemeralClient = createClient(url, anonKey, {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
          detectSessionInUrl: false,
          storage: memoryStorage as any,
          storageKey: 'porttohub-ephemeral-reauth'
        }
      });

      const { data, error } = await ephemeralClient.auth.signInWithPassword({
        email: emailLimpo,
        password: senhaLimpa
      });
      await ephemeralClient.auth.signOut().catch(() => {});

      if (error || !data?.user?.id) {
        return {
          ok: false,
          error: error
            ? formatarErroDetalhadoSupabase(error, 'Reautenticação Supabase Auth')
            : 'Credenciais inválidas no Supabase Auth.'
        };
      }
      userId = data.user.id;
    }

    if (params.expectedAuthUserId && userId !== params.expectedAuthUserId) {
      return {
        ok: false,
        error: 'A conta autenticada no Supabase Auth não corresponde ao auth_user_id vinculado a este operador.'
      };
    }

    return { ok: true, authUserId: userId };
  } catch (err: any) {
    return {
      ok: false,
      error: formatarErroDetalhadoSupabase(err, 'Falha ao validar credenciais no Supabase Auth')
    };
  }
}

/**
 * Busca operador ativo usando apenas colunas seguras (nunca select('*') nem senha)
 * dentro do condomínio autorizado para validação na troca de posto/ronda.
 */
export async function buscarOperadorParaReautenticacao(params: {
  condominioId: string;
  operadorId?: string;
  identificador?: string;
}): Promise<{ operador: any | null; error?: string }> {
  const { condominioId, operadorId, identificador } = params;
  if (!isCondominioIdValido(condominioId)) {
    return { operador: null, error: 'Condomínio inválido para validar operador.' };
  }

  try {
    if (operadorId) {
      const { data, error } = await supabase
        .from('operadores')
        .select(OPERADOR_SAFE_COLUMNS)
        .eq('id', operadorId)
        .eq('condominio_id', condominioId)
        .eq('ativo', true)
        .maybeSingle();

      if (error) return { operador: null, error: formatarErroDetalhadoSupabase(error, 'Consulta de operador') };
      return { operador: data || null };
    }

    const limpo = String(identificador || '').trim().toLowerCase();
    if (!limpo) return { operador: null, error: 'Informe o login ou e-mail do operador entrante.' };

    const ehEmail = limpo.includes('@');
    const queryBase = supabase
      .from('operadores')
      .select(OPERADOR_SAFE_COLUMNS)
      .eq('ativo', true)
      .eq('condominio_id', condominioId);

    const { data, error } = ehEmail
      ? await queryBase.ilike('email', limpo).maybeSingle()
      : await queryBase.ilike('login', limpo).maybeSingle();

    if (error) return { operador: null, error: formatarErroDetalhadoSupabase(error, 'Consulta de operador') };
    if (data) return { operador: data };

    // Fallback por nome apenas dentro do mesmo condomínio
    const { data: porNome, error: errNome } = await supabase
      .from('operadores')
      .select(OPERADOR_SAFE_COLUMNS)
      .eq('ativo', true)
      .eq('condominio_id', condominioId)
      .ilike('nome', `%${limpo}%`)
      .limit(2);

    if (errNome) return { operador: null, error: formatarErroDetalhadoSupabase(errNome, 'Consulta de operador') };
    if (Array.isArray(porNome) && porNome.length === 1) {
      return { operador: porNome[0] };
    }
    if (Array.isArray(porNome) && porNome.length > 1) {
      return { operador: null, error: 'Mais de um operador encontrado com este nome. Informe o login ou e-mail exato.' };
    }

    return { operador: null };
  } catch (err: any) {
    return { operador: null, error: formatarErroDetalhadoSupabase(err, 'Erro ao consultar operador') };
  }
}
