import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import {
  resolverContextoCondominiosOperador,
  temAcessoGlobalExplicito,
  normalizarPerfilOperador,
  ehAdminCondominio,
  ehPerfilSupervisor,
  podeGerenciarOperadoresNoCondominio,
  isCondominioIdValido,
  verificarCredenciaisOperadorSupabaseAuth
} from '../src/services/autorizacaoService.ts';
import {
  podeGerenciarOperadores as podeGerenciarOperadoresServidor
} from '../src/server/authMiddleware.ts';
import {
  buscarMoradoresDaUnidadeExata,
  validarDestinatarioAntesGravacao,
  enriquecerEncomendaComMorador
} from '../src/services/encomendasService.ts';
import {
  extrairCaminhoStorageSupabase,
  ehCaminhoPrivadoStorage,
  normalizarCaminhoStorageParaBanco,
  formatarUrlFoto
} from '../src/services/imageUtils.ts';
import {
  gerarTokenPasseSeguro,
  validarRegraPasseQR
} from '../src/services/passeQrValidation.ts';
import { PORTTOHUB_DB_VERSION } from '../src/services/porttoHubDb.ts';
import { formatarErroDetalhadoSupabase } from '../src/services/supabase.ts';
import { buildTenantCacheKey } from '../src/server/upstashClient.ts';
import {
  handleHealth,
  handleOcrEtiqueta,
  handleAdminProvisionarOperador,
  handleValidarPasseQR,
  handleCacheQuery,
  handleCacheWarmup,
  handleCacheStats,
  handleCacheClear
} from '../src/server/apiHandlers.ts';

const CONDO_A = '11111111-1111-4111-8111-111111111111';
const CONDO_B = '22222222-2222-4222-8222-222222222222';
const CONDO_C = '33333333-3333-4333-8333-333333333333';

const OP_GESTOR_A = 'aaaa1111-1111-4111-8111-111111111111';
const AUTH_GESTOR_A = 'bbbb1111-1111-4111-8111-111111111111';
const OP_ALVO_A = 'aaaa2222-2222-4222-8222-222222222222';
const AUTH_ALVO_A = 'bbbb2222-2222-4222-8222-222222222222';
const OP_ALVO_B = 'aaaa3333-3333-4333-8333-333333333333';
const AUTH_ALVO_B = 'bbbb3333-3333-4333-8333-333333333333';
const OP_GLOBAL = 'aaaa4444-4444-4444-8444-444444444444';
const AUTH_GLOBAL = 'bbbb4444-4444-4444-8444-444444444444';
const OP_INEXISTENTE = 'aaaa9999-9999-4999-8999-999999999999';

const CONDOS = [
  { id: CONDO_A, nome: 'Residencial Alpha', tipo_estrutura: 'Blocos e Apartamentos' },
  { id: CONDO_B, nome: 'Condomínio Beta', tipo_estrutura: 'Casas' },
  { id: CONDO_C, nome: 'Torres Gamma', tipo_estrutura: 'Torres e Apartamentos' }
];

function createProvisioningMockEnv() {
  const operadoresDb = [
    {
      id: OP_GESTOR_A,
      nome: 'Gestor Alpha',
      login: 'gestor.a',
      email: 'gestor.a@condo.test',
      perfil: 'admin_condominio',
      nivel_acesso: 1,
      condominio_id: CONDO_A,
      acesso_global_condominios: false,
      ativo: true,
      auth_user_id: AUTH_GESTOR_A
    },
    {
      id: OP_ALVO_A,
      nome: 'Porteiro Alpha',
      login: 'porteiro.a',
      email: 'porteiro.a@condo.test',
      perfil: 'operador',
      nivel_acesso: 3,
      condominio_id: CONDO_A,
      acesso_global_condominios: false,
      ativo: true,
      auth_user_id: AUTH_ALVO_A
    },
    {
      id: OP_ALVO_B,
      nome: 'Porteiro Beta',
      login: 'porteiro.b',
      email: 'porteiro.b@condo.test',
      perfil: 'operador',
      nivel_acesso: 3,
      condominio_id: CONDO_B,
      acesso_global_condominios: false,
      ativo: true,
      auth_user_id: AUTH_ALVO_B
    },
    {
      id: OP_GLOBAL,
      nome: 'Admin Global',
      login: 'global',
      email: 'global@porttohub.test',
      perfil: 'admin_geral',
      nivel_acesso: 0,
      condominio_id: CONDO_A,
      acesso_global_condominios: true,
      ativo: true,
      auth_user_id: AUTH_GLOBAL
    },
    {
      id: 'aaaa5555-5555-4555-8555-555555555555',
      nome: 'Novo Porteiro Sem Auth',
      login: 'novo.porteiro',
      email: 'novo.porteiro@condo.test',
      perfil: 'operador',
      nivel_acesso: 3,
      condominio_id: CONDO_A,
      acesso_global_condominios: false,
      ativo: true,
      auth_user_id: null as string | null
    }
  ];

  const authUpdates: string[] = [];
  const dbPatches: Array<{ id: string; body: any }> = [];

  const mockFetch: typeof fetch = async (input: any, init?: any) => {
    const urlStr = typeof input === 'string' ? input : input.url;
    const url = new URL(urlStr);
    const method = (init?.method || 'GET').toUpperCase();

    if (url.pathname === '/auth/v1/user') {
      const auth = init?.headers?.Authorization || init?.headers?.authorization || '';
      if (auth === 'Bearer jwt-gestor-a') {
        return new Response(JSON.stringify({ id: AUTH_GESTOR_A, email: 'gestor.a@condo.test' }), { status: 200 });
      }
      if (auth === 'Bearer jwt-global') {
        return new Response(JSON.stringify({ id: AUTH_GLOBAL, email: 'global@porttohub.test' }), { status: 200 });
      }
      return new Response(JSON.stringify({ error: 'invalid' }), { status: 401 });
    }

    if (url.pathname === '/rest/v1/operadores' && method === 'GET') {
      const idParam = url.searchParams.get('id');
      const authIdParam = url.searchParams.get('auth_user_id');
      const emailParam = url.searchParams.get('email');

      let filtered = [...operadoresDb];
      if (idParam?.startsWith('eq.')) filtered = filtered.filter(o => o.id === idParam.slice(3));
      if (authIdParam?.startsWith('eq.')) filtered = filtered.filter(o => o.auth_user_id === authIdParam.slice(3));
      if (emailParam?.startsWith('ilike.')) {
        const targetEmail = emailParam.slice(6).toLowerCase();
        filtered = filtered.filter(o => o.email.toLowerCase() === targetEmail);
      }

      return new Response(JSON.stringify(filtered), { status: 200 });
    }

    if (url.pathname === '/rest/v1/operadores' && method === 'PATCH') {
      const idParam = url.searchParams.get('id');
      const targetId = idParam?.startsWith('eq.') ? idParam.slice(3) : '';
      const patchBody = JSON.parse(String(init?.body || '{}'));
      const foundOp = operadoresDb.find(o => o.id === targetId);
      if (!foundOp) {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      Object.assign(foundOp, patchBody);
      dbPatches.push({ id: targetId, body: patchBody });
      return new Response(JSON.stringify([foundOp]), { status: 200 });
    }

    if (url.pathname === '/rest/v1/operador_condominios') {
      return new Response(JSON.stringify([]), { status: 200 });
    }

    if (url.pathname.startsWith('/auth/v1/admin/users/')) {
      const targetAuthId = decodeURIComponent(url.pathname.split('/').pop() || '');
      authUpdates.push(targetAuthId);
      return new Response(JSON.stringify({ id: targetAuthId }), { status: 200 });
    }

    if (url.pathname === '/auth/v1/admin/users' && method === 'POST') {
      const reqBody = JSON.parse(String(init?.body || '{}'));
      const emailReq = String(reqBody.email || '').toLowerCase();
      if (operadoresDb.some(o => o.email.toLowerCase() === emailReq && o.auth_user_id)) {
        return new Response(JSON.stringify({ msg: 'User already registered' }), { status: 422 });
      }
      return new Response(JSON.stringify({ id: 'bbbb5555-5555-4555-8555-555555555555', email: emailReq }), { status: 200 });
    }

    if (url.pathname === '/auth/v1/admin/users' && method === 'GET') {
      const filterEmail = (url.searchParams.get('filter') || '').toLowerCase();
      const matched = operadoresDb
        .filter(o => o.email.toLowerCase() === filterEmail && o.auth_user_id)
        .map(o => ({ id: o.auth_user_id, email: o.email }));
      return new Response(JSON.stringify({ users: matched }), { status: 200 });
    }

    return new Response(JSON.stringify({ error: `Unmocked ${method} ${url.pathname}` }), { status: 404 });
  };

  return {
    authUpdates,
    dbPatches,
    operadoresDb,
    env: {
      SUPABASE_URL: 'https://mock.supabase.co',
      SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
      SUPABASE_SERVICE_ROLE_KEY: 'mock_service_role_key_12345678901234567890',
      __fetchImpl: mockFetch
    } as any
  };
}

test('Regra A: Porteiro com 1 condomínio entra direto sem seletor', () => {
  const res = resolverContextoCondominiosOperador({
    operador: { id: 'op-1', perfil: 'operador', nivel_acesso: 3, condominio_id: CONDO_A, acesso_global_condominios: false },
    condominiosDisponiveis: CONDOS,
    vinculosExplicitosIds: [CONDO_A],
    tabelaVinculosDisponivel: true
  });

  assert.equal(res.bloqueado, false);
  assert.equal(res.ePorteiro, true);
  assert.equal(res.mostrarSeletor, false);
  assert.equal(res.podeTrocarCondominio, false);
  assert.equal(res.condominioInicialId, CONDO_A);
  assert.equal(res.condominiosPermitidos.length, 1);
});

test('Regra A: Porteiro sem condomínio ou com "todos" é bloqueado', () => {
  const res = resolverContextoCondominiosOperador({
    operador: { id: 'op-sem', perfil: 'operador', nivel_acesso: 3, condominio_id: 'todos', acesso_global_condominios: false },
    condominiosDisponiveis: CONDOS,
    vinculosExplicitosIds: [],
    tabelaVinculosDisponivel: true
  });

  assert.equal(res.bloqueado, true);
  assert.equal(res.condominiosPermitidos.length, 0);
});

test('Regra B: Supervisor com 0, 1 e 2+ condomínios vinculados', () => {
  const supZero = resolverContextoCondominiosOperador({
    operador: { id: 'sup-0', perfil: 'supervisor', nivel_acesso: 2, condominio_id: CONDO_A, acesso_global_condominios: false },
    condominiosDisponiveis: CONDOS,
    vinculosExplicitosIds: [],
    tabelaVinculosDisponivel: true
  });
  assert.equal(supZero.bloqueado, true);

  const supUm = resolverContextoCondominiosOperador({
    operador: { id: 'sup-1', perfil: 'supervisor', nivel_acesso: 2, condominio_id: CONDO_A, acesso_global_condominios: false },
    condominiosDisponiveis: CONDOS,
    vinculosExplicitosIds: [CONDO_B],
    tabelaVinculosDisponivel: true
  });
  assert.equal(supUm.bloqueado, false);
  assert.equal(supUm.mostrarSeletor, false);
  assert.equal(supUm.condominioInicialId, CONDO_B);

  const supDois = resolverContextoCondominiosOperador({
    operador: { id: 'sup-2', perfil: 'supervisor', nivel_acesso: 2, condominio_id: CONDO_A, acesso_global_condominios: false },
    condominiosDisponiveis: CONDOS,
    vinculosExplicitosIds: [CONDO_A, CONDO_C],
    tabelaVinculosDisponivel: true
  });
  assert.equal(supDois.bloqueado, false);
  assert.equal(supDois.mostrarSeletor, true);
  assert.deepEqual(supDois.condominiosPermitidos.map(c => c.id), [CONDO_A, CONDO_C]);
});

test('Regra C: Somente perfil "admin_geral" ativo com flag global explícita ganha acesso global; "master", "admin", "admin_local" e desconhecidos NÃO ganham privilégios administrativos', () => {
  const masterComFlag = {
    id: 'fake-global',
    login: 'admin',
    perfil: 'master',
    nivel_acesso: 0,
    condominio_id: 'todos',
    acesso_global_condominios: true,
    ativo: true
  };
  assert.equal(temAcessoGlobalExplicito(masterComFlag), false);
  assert.equal(ehAdminCondominio(masterComFlag), false);

  const resMaster = resolverContextoCondominiosOperador({
    operador: masterComFlag,
    condominiosDisponiveis: CONDOS,
    vinculosExplicitosIds: [],
    tabelaVinculosDisponivel: true
  });
  assert.equal(resMaster.eAdminGeral, false);
  assert.equal(resMaster.eAdminCondominio, false);
  assert.equal(resMaster.bloqueado, true);

  const adminGeralSemFlag = { ...masterComFlag, perfil: 'admin_geral', acesso_global_condominios: false };
  assert.equal(temAcessoGlobalExplicito(adminGeralSemFlag), false);

  const adminGeralComFlag = { ...masterComFlag, perfil: 'admin_geral', acesso_global_condominios: true, ativo: true };
  assert.equal(temAcessoGlobalExplicito(adminGeralComFlag), true);
  const resComFlag = resolverContextoCondominiosOperador({
    operador: adminGeralComFlag,
    condominiosDisponiveis: CONDOS,
    vinculosExplicitosIds: [],
    tabelaVinculosDisponivel: true
  });
  assert.equal(resComFlag.bloqueado, false);
  assert.equal(resComFlag.eAdminGeral, true);
  assert.equal(resComFlag.condominiosPermitidos.length, 3);
});

test('Regra D: Síndico fica restrito ao seu condomínio', () => {
  const res = resolverContextoCondominiosOperador({
    operador: { id: 'sind-1', perfil: 'sindico', nivel_acesso: 4, condominio_id: CONDO_B, acesso_global_condominios: false },
    condominiosDisponiveis: CONDOS,
    vinculosExplicitosIds: [CONDO_B, CONDO_C],
    tabelaVinculosDisponivel: true
  });
  assert.equal(res.bloqueado, false);
  assert.equal(res.eSindico, true);
  assert.equal(res.mostrarSeletor, false);
  assert.equal(res.condominioInicialId, CONDO_B);
});

test('Provisionamento Auth: gestor de um condomínio NÃO consegue alterar credenciais de outro condomínio, global ou auth_user_id arbitrário', async () => {
  const { env, authUpdates } = createProvisioningMockEnv();
  const makeReq = (body: any, token = 'jwt-gestor-a') =>
    new Request('http://localhost/api/admin/operadores/provisionar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(body)
    });

  // 1. Tentar modificar operador do Condomínio B -> 403
  const resOutroCondo = await handleAdminProvisionarOperador(
    makeReq({
      operador_id: OP_ALVO_B,
      condominio_id: CONDO_A,
      email: 'porteiro.b@condo.test',
      password: 'NovaSenha123!'
    }),
    env
  );
  assert.equal(resOutroCondo.status, 403);

  // 2. Tentar modificar conta de Admin Global -> 403
  const resGlobal = await handleAdminProvisionarOperador(
    makeReq({
      operador_id: OP_GLOBAL,
      condominio_id: CONDO_A,
      email: 'global@porttohub.test',
      password: 'NovaSenha123!'
    }),
    env
  );
  assert.equal(resGlobal.status, 403);

  // 3. Tentar passar auth_user_id arbitrário sem operador_id -> 403
  const resArbitrario = await handleAdminProvisionarOperador(
    makeReq({
      auth_user_id: AUTH_ALVO_B,
      condominio_id: CONDO_A,
      email: 'porteiro.b@condo.test',
      password: 'NovaSenha123!'
    }),
    env
  );
  assert.equal(resArbitrario.status, 403);

  // 4. Tentar tomar conta via colisão de e-mail pertencente a operador do Condomínio B -> 403
  const resColisaoEmail = await handleAdminProvisionarOperador(
    makeReq({
      condominio_id: CONDO_A,
      email: 'porteiro.b@condo.test',
      password: 'NovaSenha123!'
    }),
    env
  );
  assert.equal(resColisaoEmail.status, 403);

  // 5. operador_id inexistente -> 404
  const resInexistente = await handleAdminProvisionarOperador(
    makeReq({
      operador_id: OP_INEXISTENTE,
      condominio_id: CONDO_A,
      email: 'novo@condo.test',
      password: 'NovaSenha123!'
    }),
    env
  );
  assert.equal(resInexistente.status, 404);

  // Nenhum update Auth foi disparado nas tentativas bloqueadas
  assert.equal(authUpdates.length, 0);

  // 6. Gestor do Condomínio A pode atualizar operador legítimo do Condomínio A -> 200
  const resValido = await handleAdminProvisionarOperador(
    makeReq({
      operador_id: OP_ALVO_A,
      condominio_id: CONDO_A,
      email: 'porteiro.a@condo.test',
      password: 'NovaSenha123!'
    }),
    env
  );
  assert.equal(resValido.status, 200);
  assert.deepEqual(authUpdates, [AUTH_ALVO_A]);
});

test('Reautenticação efêmera na Passagem de Posto valida auth_user_id sem alterar sessão principal', async () => {
  const okRes = await verificarCredenciaisOperadorSupabaseAuth({
    email: 'porteiro.a@condo.test',
    password: 'SenhaCorreta123',
    expectedAuthUserId: AUTH_ALVO_A,
    authVerifier: async () => ({ userId: AUTH_ALVO_A })
  });
  assert.equal(okRes.ok, true);
  assert.equal(okRes.authUserId, AUTH_ALVO_A);

  const mismatchRes = await verificarCredenciaisOperadorSupabaseAuth({
    email: 'porteiro.a@condo.test',
    password: 'SenhaCorreta123',
    expectedAuthUserId: AUTH_ALVO_A,
    authVerifier: async () => ({ userId: AUTH_ALVO_B })
  });
  assert.equal(mismatchRes.ok, false);

  const semEmailRes = await verificarCredenciaisOperadorSupabaseAuth({
    email: '',
    password: 'SenhaCorreta123'
  });
  assert.equal(semEmailRes.ok, false);
});

test('Passe Virtual QR: geração CSPRNG, janela de horário BRT e consumo atômico concorrente sem exceder max_usos', async () => {
  // 1. Tokens únicos gerados via CSPRNG
  const tokens = new Set<string>();
  for (let i = 0; i < 25; i++) {
    const t = gerarTokenPasseSeguro();
    assert.match(t, /^PASS-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    assert.notEqual(t, 'PASS-CONV-98214');
    tokens.add(t);
  }
  assert.equal(tokens.size, 25);

  // 2. Validação de regras determinísticas em fuso America/Sao_Paulo
  const refDate = new Date('2026-08-15T17:00:00Z'); // 14:00 BRT
  assert.equal(
    validarRegraPasseQR(
      { condominio_id: CONDO_A, status: 'valido', data_validade: '2026-08-15', hora_inicio: '08:00', hora_fim: '18:00', max_usos: 1, usos_realizados: 0 },
      CONDO_A,
      refDate
    ).valido,
    true
  );
  assert.equal(
    validarRegraPasseQR(
      { condominio_id: CONDO_A, status: 'valido', data_validade: '2026-08-14', hora_inicio: '08:00', hora_fim: '18:00', max_usos: 1, usos_realizados: 0 },
      CONDO_A,
      refDate
    ).valido,
    false
  );
  assert.equal(
    validarRegraPasseQR(
      { condominio_id: CONDO_A, status: 'valido', data_validade: '2026-08-15', hora_inicio: '15:00', hora_fim: '18:00', max_usos: 1, usos_realizados: 0 },
      CONDO_A,
      refDate
    ).valido,
    false
  );
  assert.equal(
    validarRegraPasseQR(
      { condominio_id: CONDO_B, status: 'valido', data_validade: '2026-08-15', hora_inicio: '08:00', hora_fim: '18:00', max_usos: 1, usos_realizados: 0 },
      CONDO_A,
      refDate
    ).valido,
    false
  );

  // 3. Consumo concorrente no servidor com max_usos = 1 permite apenas 1 sucesso
  const hojeBr = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(new Date());

  const passeRow = {
    id: 'cccc1111-1111-4111-8111-111111111111',
    token: 'PASS-TEST-9999',
    condominio_id: CONDO_A,
    morador_nome: 'Carlos',
    unidade_bloco: 'Bloco A - 101',
    visitante_nome: 'Visitante Teste',
    tipo: 'visitante',
    data_validade: hojeBr,
    hora_inicio: '00:00',
    hora_fim: '23:59',
    max_usos: 1,
    usos_realizados: 0,
    status: 'valido'
  };

  const mockFetchQr: typeof fetch = async (input: any, init?: any) => {
    const urlStr = typeof input === 'string' ? input : input.url;
    const url = new URL(urlStr);
    const method = (init?.method || 'GET').toUpperCase();

    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'porteiro.a@condo.test' }), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operadores') {
      return new Response(JSON.stringify([{
        id: OP_ALVO_A,
        nome: 'Porteiro Alpha',
        login: 'porteiro.a',
        email: 'porteiro.a@condo.test',
        perfil: 'operador',
        nivel_acesso: 3,
        condominio_id: CONDO_A,
        acesso_global_condominios: false,
        ativo: true,
        auth_user_id: AUTH_ALVO_A
      }]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operador_condominios') {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/rpc/validar_e_consumir_passe_qr') {
      // Simula fallback CAS quando RPC não está aplicada no banco
      return new Response(JSON.stringify({ code: 'PGRST202' }), { status: 404 });
    }
    if (url.pathname === '/rest/v1/passes_virtuais_qr' && method === 'GET') {
      return new Response(JSON.stringify([{ ...passeRow }]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/passes_virtuais_qr' && method === 'PATCH') {
      const usosEsperados = Number((url.searchParams.get('usos_realizados') || '').replace('eq.', ''));
      const statusEsperado = (url.searchParams.get('status') || '').replace('eq.', '');
      if (passeRow.usos_realizados === usosEsperados && passeRow.status === statusEsperado) {
        const patchBody = JSON.parse(String(init.body || '{}'));
        passeRow.usos_realizados = patchBody.usos_realizados;
        passeRow.status = patchBody.status;
        return new Response(JSON.stringify([{ ...passeRow }]), { status: 200 });
      }
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/registros_acesso' && method === 'POST') {
      return new Response(JSON.stringify([{ id: 'dddd1111-1111-4111-8111-111111111111', condominio_id: CONDO_A }]), { status: 201 });
    }
    return new Response(JSON.stringify({}), { status: 404 });
  };

  const envQr: any = {
    SUPABASE_URL: 'https://mock.supabase.co',
    SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
    __fetchImpl: mockFetchQr
  };

  const makeQrReq = () =>
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ condominioId: CONDO_A, token: 'PASS-TEST-9999', consumir: true })
    });

  const respostas = await Promise.all([
    handleValidarPasseQR(makeQrReq(), envQr),
    handleValidarPasseQR(makeQrReq(), envQr),
    handleValidarPasseQR(makeQrReq(), envQr)
  ]);

  const statusCodes = respostas.map(r => r.status);
  assert.equal(statusCodes.filter(s => s === 200).length, 1);
  assert.equal(statusCodes.filter(s => s === 400 || s === 409).length, 2);
  assert.equal(passeRow.usos_realizados, 1);
  assert.equal(passeRow.status, 'utilizado');
});

test('Encomendas: unidade com 1 morador vs múltiplos moradores vs isolamento entre condomínios', async () => {
  const moradores = [
    { id: 'm1', condominio_id: CONDO_A, nome: 'Carlos Souza', bloco: 'A', unidade: '101' },
    { id: 'm2', condominio_id: CONDO_A, nome: 'Ana Souza', bloco: 'A', unidade: '101' },
    { id: 'm3', condominio_id: CONDO_A, nome: 'Bruno Lima', bloco: 'A', unidade: '102' },
    { id: 'm4', condominio_id: CONDO_B, nome: 'Outro Condomínio', bloco: 'A', unidade: '101' }
  ];

  const da101 = buscarMoradoresDaUnidadeExata(moradores, CONDO_A, 'A', '101', 'Blocos e Apartamentos');
  assert.equal(da101.length, 2);

  const semEscolha = await validarDestinatarioAntesGravacao({
    condominioId: CONDO_A,
    bloco: 'A',
    unidade: '101',
    moradoresCondominio: moradores,
    tipoEstrutura: 'Blocos e Apartamentos',
    consultarSupabaseSeOnline: false
  });
  assert.equal(semEscolha.valido, false);

  const comEscolha = await validarDestinatarioAntesGravacao({
    condominioId: CONDO_A,
    bloco: 'A',
    unidade: '101',
    moradorId: 'm2',
    moradoresCondominio: moradores,
    tipoEstrutura: 'Blocos e Apartamentos',
    consultarSupabaseSeOnline: false
  });
  assert.equal(comEscolha.valido, true);
  assert.equal(comEscolha.moradorId, 'm2');

  const outroCondo = await validarDestinatarioAntesGravacao({
    condominioId: CONDO_A,
    bloco: 'A',
    unidade: '101',
    moradorId: 'm4',
    moradoresCondominio: moradores,
    tipoEstrutura: 'Blocos e Apartamentos',
    consultarSupabaseSeOnline: false
  });
  assert.equal(outroCondo.valido, false);

  const unico = await validarDestinatarioAntesGravacao({
    condominioId: CONDO_A,
    bloco: 'A',
    unidade: '102',
    moradoresCondominio: moradores,
    tipoEstrutura: 'Blocos e Apartamentos',
    consultarSupabaseSeOnline: false
  });
  assert.equal(unico.valido, true);
  assert.equal(unico.moradorId, 'm3');

  const itemSemMorador = enriquecerEncomendaComMorador(
    { id: 'enc-1', condominio_id: CONDO_A, bloco: 'A', unidade: '102', morador_id: null },
    moradores,
    [],
    'Blocos e Apartamentos'
  );
  assert.equal(itemSemMorador.morador_id, null);
  assert.equal(itemSemMorador.moradores, null);
});

test('Storage privado e extração de caminhos por condomínio', () => {
  const pathRel = extrairCaminhoStorageSupabase(`condominios/${CONDO_A}/encomendas/foto.jpg`);
  assert.deepEqual(pathRel, { bucket: 'encomendas', path: `condominios/${CONDO_A}/encomendas/foto.jpg` });

  const pathPublic = extrairCaminhoStorageSupabase(
    `https://abc.supabase.co/storage/v1/object/public/encomendas/condominios/${CONDO_A}/custodia/x.jpg`
  );
  assert.deepEqual(pathPublic, { bucket: 'encomendas', path: `condominios/${CONDO_A}/custodia/x.jpg` });

  const pathSign = extrairCaminhoStorageSupabase(
    `https://abc.supabase.co/storage/v1/object/sign/encomendas/condominios/${CONDO_A}/rondas/y.jpg?token=secret`
  );
  assert.deepEqual(pathSign, { bucket: 'encomendas', path: `condominios/${CONDO_A}/rondas/y.jpg` });

  assert.equal(formatarUrlFoto('data:image/jpeg;base64,abc'), 'data:image/jpeg;base64,abc');
  assert.equal(isCondominioIdValido('todos'), false);
  assert.equal(isCondominioIdValido('global'), false);
  assert.equal(isCondominioIdValido(CONDO_A), true);
});

test('Backend API: rotas protegidas exigem Bearer JWT e chaves Redis são isoladas por condomínio', async () => {
  const mockEnv = {
    SUPABASE_URL: 'https://mock.supabase.co',
    SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890'
  };

  const healthRes = await handleHealth(mockEnv, 'node');
  assert.equal(healthRes.status, 200);
  const healthJson: any = await healthRes.json();
  assert.equal(healthJson.ok, true);
  assert.equal('SUPABASE_SERVICE_ROLE_KEY' in healthJson, false);

  const reqSemToken = (url: string, method = 'POST', body?: any) =>
    new Request(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    });

  assert.equal((await handleOcrEtiqueta(reqSemToken('http://localhost/api/ocr-etiqueta', 'POST', { imagemBase64: 'abc' }), mockEnv)).status, 401);
  assert.equal((await handleAdminProvisionarOperador(reqSemToken('http://localhost/api/admin/operadores/provisionar', 'POST', {}), mockEnv)).status, 401);
  assert.equal((await handleValidarPasseQR(reqSemToken('http://localhost/api/controle-acesso/validar-passe', 'POST', {}), mockEnv)).status, 401);
  assert.equal((await handleCacheQuery(reqSemToken('http://localhost/api/cache/query', 'POST', { table: 'moradores', condominioId: CONDO_A }), mockEnv)).status, 401);
  assert.equal((await handleCacheStats(reqSemToken('http://localhost/api/cache/stats', 'GET'), mockEnv)).status, 401);
  assert.equal((await handleCacheClear(reqSemToken('http://localhost/api/cache/clear', 'POST'), mockEnv)).status, 401);

  const keyA = buildTenantCacheKey({ table: 'moradores', condominioId: CONDO_A });
  const keyB = buildTenantCacheKey({ table: 'moradores', condominioId: CONDO_B });
  assert.ok(keyA.startsWith(`porttohub:v1:condo:${CONDO_A}:moradores:`));
  assert.ok(keyB.startsWith(`porttohub:v1:condo:${CONDO_B}:moradores:`));
  assert.notEqual(keyA, keyB);
});

test('Auditoria de segurança, migrações SQL e remoção de fluxos legados inseguros', () => {
  assert.equal(PORTTOHUB_DB_VERSION, 2);

  assert.equal(fs.existsSync(path.resolve('src/services/documentOcrService.ts')), false);
  assert.equal(fs.existsSync(path.resolve('src/components/ModalLeitorDocumentoOCR.tsx')), false);
  assert.equal(fs.existsSync(path.resolve('src/components/AbaModelosDocumentosOCR.tsx')), false);

  const serverCode = fs.readFileSync(path.resolve('server.ts'), 'utf8');
  const workerCode = fs.readFileSync(path.resolve('src/worker.ts'), 'utf8');
  const appCode = fs.readFileSync(path.resolve('src/App.tsx'), 'utf8');
  const passagemCode = fs.readFileSync(path.resolve('src/pages/PassagemPosto.tsx'), 'utf8');
  const rondasCode = fs.readFileSync(path.resolve('src/pages/Rondas.tsx'), 'utf8');
  const cadastrosCode = fs.readFileSync(path.resolve('src/pages/Cadastros.tsx'), 'utf8');
  const acessoServiceCode = fs.readFileSync(path.resolve('src/services/controleAcessoService.ts'), 'utf8');
  const acessoPageCode = fs.readFileSync(path.resolve('src/pages/ControleAcesso.tsx'), 'utf8');
  const apiHandlersCode = fs.readFileSync(path.resolve('src/server/apiHandlers.ts'), 'utf8');
  const sql01 = fs.readFileSync(path.resolve('supabase/sql/01_CRIAR_TABELAS_DO_ZERO.sql'), 'utf8');
  const sql07 = fs.readFileSync(path.resolve('supabase/sql/07_STORAGE_PRIVADO_POLICIES.sql'), 'utf8');
  const dbDoctor = fs.readFileSync(path.resolve('src/services/databaseDoctor.ts'), 'utf8');

  // Infraestrutura antiga e dados hardcoded removidos
  assert.equal(serverCode.includes('kkeizhscivyfjgetnbke'), false);
  assert.equal(appCode.includes("'2468'"), false);
  assert.equal(apiHandlersCode.includes('grupocaetanodigital-creator'), false);
  assert.equal(acessoServiceCode.includes('PASS-CONV-98214'), false);
  assert.equal(acessoPageCode.includes('PASS-CONV-98214'), false);

  // Autenticação por coluna senha / localStorage eliminada
  assert.equal(passagemCode.includes(".eq('senha'"), false);
  assert.equal(passagemCode.includes("localStorage.setItem('infport_sessao_ativa_v1'"), false);
  assert.equal(rondasCode.includes('opData.senha'), false);
  assert.equal(appCode.includes(".from('operadores')\n          .select('*')"), false);
  assert.equal(cadastrosCode.includes(".from('operadores').insert([novoOp]).select()."), false);

  // Schema e storage policies limpos
  assert.equal(/^\s*senha\s+TEXT/im.test(sql01), false);
  assert.equal(/^\s*senha\s+TEXT/im.test(dbDoctor), false);
  assert.equal(sql07.includes("IS DISTINCT FROM 'condominios'"), false);

  // Nenhuma referência a service_role no código cliente src/services ou src/components ou src/pages
  for (const dir of ['src/services', 'src/components', 'src/pages']) {
    const absDir = path.resolve(dir);
    for (const file of fs.readdirSync(absDir)) {
      if (!file.endsWith('.ts') && !file.endsWith('.tsx')) continue;
      const content = fs.readFileSync(path.join(absDir, file), 'utf8');
      assert.equal(content.includes('SUPABASE_SERVICE_ROLE_KEY'), false, `${dir}/${file} não pode referenciar SUPABASE_SERVICE_ROLE_KEY`);
    }
  }
});

test('Formatação detalhada de erros Supabase (rede, apikey, RLS e Auth)', () => {
  const errRede = formatarErroDetalhadoSupabase({ message: 'Failed to fetch' }, 'Auth');
  assert.ok(errRede.includes('Failed to fetch'));
  assert.ok(errRede.toLowerCase().includes('rede'));

  const errKey = formatarErroDetalhadoSupabase({ status: 401, message: 'Invalid API key' }, 'Auth');
  assert.ok(errKey.includes('HTTP 401'));
  assert.ok(errKey.includes('Invalid API key'));

  const errRls = formatarErroDetalhadoSupabase({ code: '42501', message: 'permission denied for table operadores' }, 'Operadores');
  assert.ok(errRls.includes('42501'));
  assert.ok(errRls.toLowerCase().includes('rls'));
});

test('Infraestrutura oficial: diagnóstico seguro em banco vazio, Worker porttohubpro, /env-config.js e README sem contradições', () => {
  const sql00b = fs.readFileSync(path.resolve('supabase/sql/00B_DIAGNOSTICO_DESTINO.sql'), 'utf8');
  const sql07 = fs.readFileSync(path.resolve('supabase/sql/07_STORAGE_PRIVADO_POLICIES.sql'), 'utf8');
  const sql09 = fs.readFileSync(path.resolve('supabase/sql/09_VALIDACAO_SEGURANCA.sql'), 'utf8');
  const wranglerRaw = fs.readFileSync(path.resolve('wrangler.jsonc'), 'utf8');
  const wranglerCfg = JSON.parse(wranglerRaw);
  const swCode = fs.readFileSync(path.resolve('public/sw.js'), 'utf8');
  const readmeCode = fs.readFileSync(path.resolve('README.md'), 'utf8');

  // 00B não pode conter FROM public.<tabela> direto fora de string dinâmica protegida por to_regclass
  assert.equal(/^\s*FROM\s+public\.(operadores|condominios|moradores|encomendas_itens)\b/im.test(sql00b), false);
  assert.ok(sql00b.includes("to_regclass('public.operadores')"));
  assert.ok(sql00b.includes("to_regclass('public.condominios')"));
  assert.ok(sql00b.includes("to_regclass('public.moradores')"));
  assert.ok(sql00b.includes("to_regclass('public.encomendas_itens')"));

  // 07 e 09 consistentes com sequência única oficial
  assert.equal(sql07.includes('somente DEPOIS que a versão atualizada'), false);
  assert.ok(sql09.includes('RESUMO CONSOLIDADO'));

  // Worker existente porttohubpro + /env-config.js antes de assets
  assert.equal(wranglerCfg.name, 'porttohubpro');
  assert.ok(Array.isArray(wranglerCfg.assets?.run_worker_first));
  assert.ok(wranglerCfg.assets.run_worker_first.includes('/api/*'));
  assert.ok(wranglerCfg.assets.run_worker_first.includes('/env-config.js'));

  // Service worker não pode cachear /env-config.js
  assert.ok(swCode.includes("url.pathname === '/env-config.js'"));

  // README explicitamente proíbe rodar script 10 na instalação normal
  assert.ok(readmeCode.includes('NÃO execute `10_ROLLBACK_OU_RECUPERACAO.sql` durante a instalação normal'));
});

test('[Mock/Unit] 4 perfis oficiais, regra estrita de condomínio principal e bloqueio de auto-escalação', async () => {
  const opGlobal = {
    id: OP_GLOBAL,
    perfil: 'admin_geral',
    nivel_acesso: 0,
    condominio_id: null,
    acesso_global_condominios: true
  };
  const opAdminLocal = {
    id: OP_GESTOR_A,
    perfil: 'admin_condominio',
    nivel_acesso: 1,
    condominio_id: CONDO_A,
    acesso_global_condominios: false
  };
  const opSupervisor = {
    id: 'sup-oficial',
    perfil: 'supervisor',
    nivel_acesso: 2,
    condominio_id: CONDO_A,
    acesso_global_condominios: false
  };
  const opComum = {
    id: OP_ALVO_A,
    perfil: 'operador',
    nivel_acesso: 3,
    condominio_id: CONDO_A,
    acesso_global_condominios: false
  };
  const opFalsoAdminGlobal = {
    id: 'falso-global',
    login: 'admin',
    perfil: 'admin_geral',
    nivel_acesso: 0,
    condominio_id: CONDO_A,
    acesso_global_condominios: false
  };

  assert.equal(normalizarPerfilOperador(opGlobal), 'admin_geral');
  assert.equal(normalizarPerfilOperador(opAdminLocal), 'admin_condominio');
  assert.equal(normalizarPerfilOperador(opSupervisor), 'supervisor');
  assert.equal(normalizarPerfilOperador(opComum), 'operador');
  // Sem acesso_global_condominios = true, mesmo perfil='admin_geral' / nivel=0 / login='admin' NÃO vira admin_geral
  assert.notEqual(normalizarPerfilOperador(opFalsoAdminGlobal), 'admin_geral');
  assert.equal(temAcessoGlobalExplicito(opFalsoAdminGlobal), false);

  // Regra estrita: admin_condominio gerencia APENAS seu condomínio principal, nunca secundários nem globalmente
  assert.equal(ehAdminCondominio(opAdminLocal), true);
  assert.equal(podeGerenciarOperadoresNoCondominio(opAdminLocal, CONDO_A), true);
  assert.equal(podeGerenciarOperadoresNoCondominio(opAdminLocal, CONDO_B), false);
  assert.equal(podeGerenciarOperadoresNoCondominio(opAdminLocal, null), false);

  // Supervisor e operador NUNCA recebem poder administrativo de gestão de operadores
  assert.equal(ehPerfilSupervisor(opSupervisor), true);
  assert.equal(podeGerenciarOperadoresNoCondominio(opSupervisor, CONDO_A), false);
  assert.equal(podeGerenciarOperadoresNoCondominio(opComum, CONDO_A), false);
  assert.equal(podeGerenciarOperadoresNoCondominio(opGlobal, CONDO_B), true);
  assert.equal(podeGerenciarOperadoresNoCondominio(opGlobal, null), true);

  // Espelho exato no servidor (authMiddleware)
  const serverCtxLocal: any = {
    eAdminGlobal: false,
    perfilNormalizado: 'admin_condominio',
    operador: opAdminLocal,
    allowedCondominioIds: new Set([CONDO_A, CONDO_B]) // Mesmo com vínculo secundário em CONDO_B
  };
  assert.equal(podeGerenciarOperadoresServidor(serverCtxLocal, CONDO_A), true);
  assert.equal(podeGerenciarOperadoresServidor(serverCtxLocal, CONDO_B), false); // Bloqueado em secundário!
  assert.equal(podeGerenciarOperadoresServidor(serverCtxLocal, null), false);

  const serverCtxSup: any = {
    eAdminGlobal: false,
    perfilNormalizado: 'supervisor',
    operador: opSupervisor,
    allowedCondominioIds: new Set([CONDO_A, CONDO_B])
  };
  assert.equal(podeGerenciarOperadoresServidor(serverCtxSup, CONDO_A), false);

  // Endpoint administrativo bloqueia auto-edição e criação de admin_geral por admin_condominio
  const { env, authUpdates } = createProvisioningMockEnv();
  const makeReq = (body: any) =>
    new Request('http://localhost/api/admin/operadores/provisionar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-gestor-a' },
      body: JSON.stringify(body)
    });

  const resSelf = await handleAdminProvisionarOperador(
    makeReq({ operador_id: OP_GESTOR_A, condominio_id: CONDO_A, email: 'gestor.a@condo.test', password: 'NovaSenha123!' }),
    env
  );
  assert.equal(resSelf.status, 403);

  const resEscalar = await handleAdminProvisionarOperador(
    makeReq({ condominio_id: CONDO_A, email: 'novo@condo.test', password: 'NovaSenha123!', perfil: 'admin_geral', acesso_global_condominios: true }),
    env
  );
  assert.equal(resEscalar.status, 403);
  assert.equal(authUpdates.length, 0);
});

test('[Mock/Unit] Storage privado: normalização de caminhos condominios/ e operadores/ e prevenção de vazamento em telas', () => {
  const pathCondo = `condominios/${CONDO_A}/ocorrencias/evidencia.jpg`;
  const pathAvatar = `operadores/${AUTH_GLOBAL}/avatar.jpg`;
  const signedAvatar = `https://abc.supabase.co/storage/v1/object/sign/encomendas/operadores/${AUTH_GLOBAL}/avatar.jpg?token=expira123`;

  assert.equal(ehCaminhoPrivadoStorage(pathCondo), true);
  assert.equal(ehCaminhoPrivadoStorage(pathAvatar), true);
  assert.equal(ehCaminhoPrivadoStorage('https://exemplo.com/publica.jpg'), false);
  assert.deepEqual(extrairCaminhoStorageSupabase(pathAvatar), { bucket: 'encomendas', path: pathAvatar });
  assert.equal(normalizarCaminhoStorageParaBanco(signedAvatar), pathAvatar);
  assert.equal(normalizarCaminhoStorageParaBanco(pathCondo), pathCondo);

  const modalPerfilCode = fs.readFileSync(path.resolve('src/components/ModalMeuPerfil.tsx'), 'utf8');
  assert.equal(modalPerfilCode.includes('comprimirImagemBase64'), false);
  assert.ok(modalPerfilCode.includes('escopoUsuarioAuthId'));
  assert.ok(modalPerfilCode.includes("fotoNormalizada.startsWith('data:')"));

  const custodiaCode = fs.readFileSync(path.resolve('src/pages/Custodia.tsx'), 'utf8');
  assert.equal(custodiaCode.includes('href={fotoAmpliadaModal.url}'), false);
  assert.ok(custodiaCode.includes('resolverUrlFotoPrivada'));

  const encomendasCode = fs.readFileSync(path.resolve('src/pages/Encomendas.tsx'), 'utf8');
  assert.equal(encomendasCode.includes('href={modalFotoAmpliada}'), false);

  const ocorrenciasCode = fs.readFileSync(path.resolve('src/pages/Ocorrencias.tsx'), 'utf8');
  assert.equal(ocorrenciasCode.includes('${item.foto_url}'), false);
  assert.ok(ocorrenciasCode.includes('resolverUrlFotoPrivada'));

  const controleAcessoCode = fs.readFileSync(path.resolve('src/pages/ControleAcesso.tsx'), 'utf8');
  assert.equal(controleAcessoCode.includes('reg.nome_pessoa'), false);

  const configCode = fs.readFileSync(path.resolve('src/pages/Configuracoes.tsx'), 'utf8');
  assert.equal(configCode.includes("login?.toLowerCase() === 'admin'"), false);
  assert.ok(configCode.includes('temAcessoGlobalExplicito(usuarioLogado)'));

  const lembretesCode = fs.readFileSync(path.resolve('src/components/ModalLembretesPortaria.tsx'), 'utf8');
  assert.equal(lembretesCode.includes('operadorAtual?.nivel_acesso === 0'), false);

  const appCode = fs.readFileSync(path.resolve('src/App.tsx'), 'utf8');
  assert.equal(appCode.includes('eSuperAdminGlobal: eAdmin'), false);
});

test('[Mock/Unit] Passe QR RPC retorna registro + registro_id e scripts SQL 05/05B/06/07 consolidam regras oficiais', async () => {
  const mockRegistro = {
    id: 'eeee1111-1111-4111-8111-111111111111',
    condominio_id: CONDO_A,
    nome: 'Visitante QR',
    status: 'presente'
  };

  const mockFetchRpc: typeof fetch = async (input: any) => {
    const urlStr = typeof input === 'string' ? input : input.url;
    const url = new URL(urlStr);
    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'porteiro.a@condo.test' }), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operadores') {
      return new Response(JSON.stringify([{
        id: OP_ALVO_A,
        nome: 'Porteiro Alpha',
        perfil: 'operador',
        nivel_acesso: 3,
        condominio_id: CONDO_A,
        acesso_global_condominios: false,
        ativo: true,
        auth_user_id: AUTH_ALVO_A
      }]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operador_condominios') {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/rpc/validar_e_consumir_passe_qr') {
      return new Response(JSON.stringify({
        valido: true,
        consumido: true,
        registro_id: mockRegistro.id,
        registro: mockRegistro,
        passe: { id: 'p-1', token: 'PASS-OK12-3456', status: 'utilizado', usos_realizados: 1, max_usos: 1 }
      }), { status: 200 });
    }
    return new Response('{}', { status: 404 });
  };

  const res = await handleValidarPasseQR(
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ condominioId: CONDO_A, token: 'PASS-OK12-3456', consumir: true })
    }),
    {
      SUPABASE_URL: 'https://mock.supabase.co',
      SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
      __fetchImpl: mockFetchRpc
    } as any
  );

  assert.equal(res.status, 200);
  const body: any = await res.json();
  assert.equal(body.registro_id, mockRegistro.id);
  assert.deepEqual(body.registro, mockRegistro);

  const sql05 = fs.readFileSync(path.resolve('supabase/sql/05_FUNCOES_AUTORIZACAO.sql'), 'utf8');
  const sql05b = fs.readFileSync(path.resolve('supabase/sql/05B_FUNCOES_PASSE_QR.sql'), 'utf8');
  const sql06 = fs.readFileSync(path.resolve('supabase/sql/06_RLS_TABELAS_MULTI_TENANT.sql'), 'utf8');
  const sql07 = fs.readFileSync(path.resolve('supabase/sql/07_STORAGE_PRIVADO_POLICIES.sql'), 'utf8');

  // 05: admin_condominio gerencia SOMENTE próprio condomínio principal (sem operador_condominios)
  const trechoFnGerenciar = sql05.split('CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores(p_condominio_id TEXT)')[1]
    .split('CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores(p_condominio_id UUID)')[0];
  assert.equal(trechoFnGerenciar.includes('operador_condominios'), false);
  assert.match(trechoFnGerenciar, /lower\((?:trim\()?COALESCE\(o\.perfil, ''\)\)?\) = 'admin_condominio'/);
  assert.equal(trechoFnGerenciar.includes('admin_local'), false);
  assert.equal(trechoFnGerenciar.includes("'master'"), false);
  assert.equal(trechoFnGerenciar.includes("'admin'"), false);

  // 05B: retorna ambos registro_id e registro completo
  assert.ok(sql05b.includes("'registro_id', v_registro_id"));
  assert.ok(sql05b.includes("'registro', (SELECT to_jsonb(r) FROM public.registros_acesso r WHERE r.id = v_registro_id)"));

  // 06: trigger + políticas RLS reconciliadas
  assert.ok(sql06.includes('trg_proteger_campos_operador'));
  assert.ok(sql06.includes('operador_preserva_proprio_perfil'));
  assert.ok(sql06.includes('operador_pode_editar_alvo_local'));
  assert.ok(sql06.includes('operador_id IS DISTINCT FROM public.operador_atual_id()'));

  // 07: políticas privadas para condominios/ e operadores/{auth.uid()}/
  assert.ok(sql07.includes('porttohub_storage_operadores_select'));
  assert.ok(sql07.includes("(storage.foldername(name))[2] = auth.uid()::text"));
});

test('[Auditoria Completa 1-12] Proteção de permissões/perfil, usuários inativos, vínculo Auth e fail-closed no frontend/backend', async () => {
  const { authenticateRequest } = await import('../src/server/authMiddleware.ts');
  const {
    salvarPermissoesOperador,
    salvarNivelAcesso,
    excluirNivelAcesso
  } = await import('../src/services/permissoesService.ts');
  const { supabase } = await import('../src/services/supabase.ts');

  // 1 & 2: Frontend fail-closed — se Supabase rejeitar (ex: 42501 RLS ou trigger), NÃO escreve cache local e lança erro
  const origFrom = supabase.from.bind(supabase);
  const origStorage = (globalThis as any).localStorage;
  const mockStore = new Map<string, string>();
  (globalThis as any).localStorage = {
    getItem: (k: string) => (mockStore.has(k) ? mockStore.get(k)! : null),
    setItem: (k: string, v: string) => { mockStore.set(k, String(v)); },
    removeItem: (k: string) => { mockStore.delete(k); }
  };

  try {
    const errRes = {
      data: null,
      error: { code: '42501', message: 'Acesso negado: não é permitido alterar os próprios campos administrativos, permissões ou vínculo de autenticação.' }
    };
    const cfgErrRes = {
      data: null,
      error: { code: '42501', message: 'new row violates row-level security policy for table "configuracoes"' }
    };
    (supabase as any).from = (table: string) => ({
      update: () => ({
        eq: () => {
          const res = table === 'configuracoes' ? cfgErrRes : errRes;
          return Object.assign(Promise.resolve(res), {
            select: async () => res
          });
        }
      }),
      upsert: async () => cfgErrRes
    });

    await assert.rejects(
      () => salvarPermissoesOperador(OP_ALVO_A, { encomendas: { visualizar: true } } as any, 'porteiro.a', CONDO_A),
      /42501|permiss|Acesso negado/i
    );
    assert.equal(mockStore.has(`porttohub_operador_permissoes_${OP_ALVO_A}`), false);

    await assert.rejects(
      () => salvarNivelAcesso({ id: 'custom_1', nome: 'Teste', permissoes: {} }, CONDO_A),
      /42501|Permissão negada/i
    );

    await assert.rejects(
      () => excluirNivelAcesso('custom_1', CONDO_A),
      /42501|Falha ao excluir/i
    );
  } finally {
    (supabase as any).from = origFrom;
    (globalThis as any).localStorage = origStorage;
  }

  // 8 & 9: Usuário inativo e usuário com auth_user_id incompatível são bloqueados no servidor
  const makeAuthFetch = (opRow: any): typeof fetch => async (input: any) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'porteiro.a@condo.test' }), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operadores') {
      const byAuth = url.searchParams.get('auth_user_id');
      if (byAuth && opRow.auth_user_id !== AUTH_ALVO_A) {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      return new Response(JSON.stringify([opRow]), { status: 200 });
    }
    return new Response(JSON.stringify([]), { status: 200 });
  };

  const authInactive = await authenticateRequest(
    new Request('http://localhost/api/cache/stats', { headers: { Authorization: 'Bearer jwt-inativo' } }),
    {
      SUPABASE_URL: 'https://mock.supabase.co',
      SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
      __fetchImpl: makeAuthFetch({
        id: OP_ALVO_A,
        condominio_id: CONDO_A,
        perfil: 'operador',
        ativo: false,
        auth_user_id: AUTH_ALVO_A
      })
    } as any
  );
  assert.equal(authInactive.ok, false);
  if (!authInactive.ok) assert.equal(authInactive.status, 403);

  const authMismatch = await authenticateRequest(
    new Request('http://localhost/api/cache/stats', { headers: { Authorization: 'Bearer jwt-outro' } }),
    {
      SUPABASE_URL: 'https://mock.supabase.co',
      SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
      __fetchImpl: makeAuthFetch({
        id: OP_ALVO_B,
        condominio_id: CONDO_B,
        email: 'porteiro.a@condo.test',
        perfil: 'operador',
        ativo: true,
        auth_user_id: AUTH_ALVO_B // Pertence a outra conta Auth!
      })
    } as any
  );
  assert.equal(authMismatch.ok, false);
  if (!authMismatch.ok) assert.equal(authMismatch.status, 403);

  // 10, 11, 12: Cross-condominio bloqueado em /api/cache/query e Cadastros sem fallback inseguro
  const mockFetchCrossCondo: typeof fetch = async (input: any) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'porteiro.a@condo.test' }), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operadores') {
      return new Response(JSON.stringify([{
        id: OP_ALVO_A,
        condominio_id: CONDO_A,
        perfil: 'operador',
        ativo: true,
        acesso_global_condominios: false,
        auth_user_id: AUTH_ALVO_A
      }]), { status: 200 });
    }
    return new Response(JSON.stringify([]), { status: 200 });
  };
  const crossCacheRes = await handleCacheQuery(
    new Request('http://localhost/api/cache/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ table: 'moradores', condominioId: CONDO_B })
    }),
    {
      SUPABASE_URL: 'https://mock.supabase.co',
      SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
      __fetchImpl: mockFetchCrossCondo
    } as any
  );
  assert.equal(crossCacheRes.status, 403);

  const cadastrosCode = fs.readFileSync(path.resolve('src/pages/Cadastros.tsx'), 'utf8');
  assert.equal(cadastrosCode.includes('Fallback: salvando operador sem colunas extras'), false);
  assert.equal(cadastrosCode.includes('Fallback: cadastrando operador sem colunas extras'), false);
});

test('[Auditoria Completa 16-23] QR Code: bloqueio de spoofing de operador, erro RPC fail-closed, sem consumo não altera usos e registro de entrada correto', async () => {
  // 16a: Cliente envia operadorNome falso no payload, mas handler e RPC recebem apenas o operador real da sessão autenticada
  let rpcPayloadCapturado: any = null;
  const mockFetchAntiSpoof: typeof fetch = async (input: any, init?: any) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'porteiro.a@condo.test' }), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operadores') {
      return new Response(JSON.stringify([{
        id: OP_ALVO_A,
        nome: 'Porteiro Real Alpha',
        login: 'porteiro.a',
        perfil: 'operador',
        condominio_id: CONDO_A,
        acesso_global_condominios: false,
        ativo: true,
        auth_user_id: AUTH_ALVO_A
      }]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operador_condominios') {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/rpc/validar_e_consumir_passe_qr') {
      rpcPayloadCapturado = JSON.parse(String(init?.body || '{}'));
      return new Response(JSON.stringify({
        valido: true,
        consumido: true,
        registro_id: 'rrrr1111-1111-4111-8111-111111111111',
        registro: {
          id: 'rrrr1111-1111-4111-8111-111111111111',
          condominio_id: CONDO_A,
          operador_entrada_nome: 'Porteiro Real Alpha',
          status: 'presente'
        },
        passe: { id: 'pppp1111-1111-4111-8111-111111111111', usos_realizados: 1, max_usos: 1, status: 'utilizado' }
      }), { status: 200 });
    }
    return new Response('{}', { status: 404 });
  };

  const resSpoof = await handleValidarPasseQR(
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({
        condominioId: CONDO_A,
        token: 'PASS-REAL-0001',
        consumir: true,
        operadorNome: 'FALSO_ADMIN_INVASOR',
        p_operador_nome: 'FALSO_ADMIN_INVASOR'
      })
    }),
    {
      SUPABASE_URL: 'https://mock.supabase.co',
      SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
      __fetchImpl: mockFetchAntiSpoof
    } as any
  );
  assert.equal(resSpoof.status, 200);
  assert.equal(rpcPayloadCapturado?.p_operador_nome, 'Porteiro Real Alpha');
  assert.notEqual(rpcPayloadCapturado?.p_operador_nome, 'FALSO_ADMIN_INVASOR');

  // 16b: Erro real na RPC (500) NÃO deve acionar fallback CAS — deve falhar fechado (502)
  let fallbackTentado = false;
  const mockFetchRpc500: typeof fetch = async (input: any) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'porteiro.a@condo.test' }), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operadores') {
      return new Response(JSON.stringify([{
        id: OP_ALVO_A,
        nome: 'Porteiro Real Alpha',
        condominio_id: CONDO_A,
        ativo: true,
        auth_user_id: AUTH_ALVO_A
      }]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operador_condominios') {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/rpc/validar_e_consumir_passe_qr') {
      return new Response(JSON.stringify({ message: 'internal db error' }), { status: 500 });
    }
    if (url.pathname === '/rest/v1/passes_virtuais_qr') {
      fallbackTentado = true;
    }
    return new Response('{}', { status: 404 });
  };
  const resRpc500 = await handleValidarPasseQR(
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ condominioId: CONDO_A, token: 'PASS-REAL-0001', consumir: true })
    }),
    {
      SUPABASE_URL: 'https://mock.supabase.co',
      SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
      __fetchImpl: mockFetchRpc500
    } as any
  );
  assert.equal(resRpc500.status, 502);
  assert.equal(fallbackTentado, false);

  // 19, 20, 22, 23: Passe outro condomínio recusado, limite atingido recusado, validação sem consumo não altera passe
  const hojeBr = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(new Date());

  const passeMulti = {
    id: 'cccc2222-2222-4222-8222-222222222222',
    token: 'PASS-READ-ONLY',
    condominio_id: CONDO_A,
    morador_nome: 'Maria',
    unidade_bloco: 'B - 202',
    visitante_nome: 'Visitante Leitura',
    tipo: 'visitante',
    data_validade: hojeBr,
    hora_inicio: '00:00',
    hora_fim: '23:59',
    max_usos: 2,
    usos_realizados: 1,
    status: 'valido'
  };
  let patchChamado = false;
  let registroInserido = false;
  const mockFetchReadOnly: typeof fetch = async (input: any, init?: any) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    const method = (init?.method || 'GET').toUpperCase();
    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'porteiro.a@condo.test' }), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operadores') {
      return new Response(JSON.stringify([{ id: OP_ALVO_A, nome: 'Porteiro', condominio_id: CONDO_A, ativo: true, auth_user_id: AUTH_ALVO_A }]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operador_condominios') {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/rpc/validar_e_consumir_passe_qr') {
      return new Response(JSON.stringify({ code: 'PGRST202' }), { status: 404 });
    }
    if (url.pathname === '/rest/v1/passes_virtuais_qr' && method === 'GET') {
      return new Response(JSON.stringify([{ ...passeMulti }]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/passes_virtuais_qr' && method === 'PATCH') {
      patchChamado = true;
    }
    if (url.pathname === '/rest/v1/registros_acesso' && method === 'POST') {
      registroInserido = true;
    }
    return new Response('{}', { status: 404 });
  };
  const envRo: any = {
    SUPABASE_URL: 'https://mock.supabase.co',
    SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
    __fetchImpl: mockFetchReadOnly
  };
  const resOutroCondoPasse = await handleValidarPasseQR(
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ condominioId: CONDO_B, token: 'PASS-READ-ONLY', consumir: true })
    }),
    envRo
  );
  assert.equal(resOutroCondoPasse.status, 403);

  const resSemConsumo = await handleValidarPasseQR(
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ condominioId: CONDO_A, token: 'PASS-READ-ONLY', consumir: false })
    }),
    envRo
  );
  assert.equal(resSemConsumo.status, 200);
  assert.equal(patchChamado, false);
  assert.equal(registroInserido, false);
  assert.equal(passeMulti.usos_realizados, 1);

  assert.equal(
    validarRegraPasseQR({ ...passeMulti, usos_realizados: 2, max_usos: 2 }, CONDO_A).valido,
    false
  );
});

test('[Auditoria SQL 05/05B/06/07/08/09/11/12] Trigger SECURITY INVOKER, proteção permissoes, revogação anon/PUBLIC/TRUNCATE, 8 policies Storage, constraint e auditoria read-only', () => {
  const sql05 = fs.readFileSync(path.resolve('supabase/sql/05_FUNCOES_AUTORIZACAO.sql'), 'utf8');
  const sql05b = fs.readFileSync(path.resolve('supabase/sql/05B_FUNCOES_PASSE_QR.sql'), 'utf8');
  const sql06 = fs.readFileSync(path.resolve('supabase/sql/06_RLS_TABELAS_MULTI_TENANT.sql'), 'utf8');
  const sql07 = fs.readFileSync(path.resolve('supabase/sql/07_STORAGE_PRIVADO_POLICIES.sql'), 'utf8');
  const sql08 = fs.readFileSync(path.resolve('supabase/sql/08_INDICES_E_CONSTRAINTS.sql'), 'utf8');
  const sql09 = fs.readFileSync(path.resolve('supabase/sql/09_VALIDACAO_SEGURANCA.sql'), 'utf8');
  const sql11 = fs.readFileSync(path.resolve('supabase/sql/11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql'), 'utf8');
  const sql12 = fs.readFileSync(path.resolve('supabase/sql/12_AUDITORIA_FINAL_SEGURANCA.sql'), 'utf8');

  // Trigger proteger_campos_operador NÃO pode ser SECURITY DEFINER (evita bypass current_user=postgres)
  for (const [nome, conteudo] of [['06', sql06], ['11', sql11]] as const) {
    const triggerFn = conteudo.split('CREATE OR REPLACE FUNCTION public.proteger_campos_operador()')[1].split('REVOKE ALL ON FUNCTION public.proteger_campos_operador()')[0];
    assert.equal(triggerFn.includes('SECURITY DEFINER'), false, `${nome}: proteger_campos_operador não pode usar SECURITY DEFINER`);
    assert.ok(triggerFn.includes('SECURITY INVOKER'), `${nome}: proteger_campos_operador deve usar SECURITY INVOKER`);
    assert.ok(triggerFn.includes('NEW.permissoes'), `${nome}: proteger_campos_operador deve proteger coluna permissoes`);
    assert.ok(conteudo.includes('REVOKE TRUNCATE, TRIGGER, REFERENCES ON TABLE public.%I FROM authenticated;'), `${nome}: deve revogar TRUNCATE/TRIGGER/REFERENCES`);
    assert.ok(conteudo.includes('REVOKE ALL ON TABLE public.%I FROM PUBLIC, anon;'), `${nome}: deve revogar PUBLIC e anon das tabelas`);
    assert.equal(/\bFOR\s+ALL\s+TO\s+authenticated\b/i.test(conteudo), false, `${nome}: não deve usar política genérica FOR ALL`);
  }

  // 05 e 11 protegem permissoes em operador_preserva_proprio_perfil e revogam PUBLIC, anon
  assert.ok(sql05.includes('operador_auth_email_corresponde'));
  assert.ok(sql05.includes('COALESCE(cur.permissoes'));
  assert.ok(sql05.includes('FROM PUBLIC, anon;'));

  // 05B e 11 derivam operador exclusivamente de auth.uid()
  assert.ok(sql05b.includes('WHERE o.auth_user_id = auth.uid()'));
  assert.ok(sql05b.includes('FROM PUBLIC, anon;'));

  // 07 possui todas as 8 políticas privadas + UUID check + operador ativo
  assert.ok(sql07.includes('porttohub_storage_operadores_delete'));
  assert.ok(sql07.includes('public.operador_atual_id() IS NOT NULL'));

  // 08 e 11 validam chk_passes_qr_usos_limite com checagem prévia sem apagar dados
  assert.ok(sql08.includes('VALIDATE CONSTRAINT chk_passes_qr_usos_limite'));
  assert.ok(sql11.includes('VALIDATE CONSTRAINT chk_passes_qr_usos_limite'));
  const sql11SemComentarios = sql11.replace(/--[^\n]*/g, '');
  assert.equal(/\bDROP\s+TABLE\b/i.test(sql11SemComentarios), false);
  assert.equal(/\bTRUNCATE\b/i.test(sql11SemComentarios.replace(/REVOKE TRUNCATE[^\n]*/g, '')), false);

  // 09 e 12 auditam privilégios de funções e classificam OK / ATENÇÃO / FALHA / NÃO TESTADO
  assert.ok(sql09.includes('has_function_privilege'));
  assert.ok(sql12.includes('has_function_privilege'));
  assert.ok(
    sql12.includes("'OK'") &&
    sql12.includes("'ATENÇÃO'") &&
    sql12.includes("'FALHA'") &&
    sql12.includes("'NÃO TESTADO'")
  );
});

test('[Segunda Rodada] Provisionamento service_role vincula auth_user_id, OCR/QR/Cache bloqueiam por permissoes e Passe QR concorrente (2 chamadas) sem bypass', async () => {
  // 1. Provisionamento com operador_id sem auth_user_id cria usuário no Auth e faz PATCH service_role na tabela operadores
  const { env: provEnv, dbPatches, operadoresDb } = createProvisioningMockEnv();
  const OP_SEM_AUTH = 'aaaa5555-5555-4555-8555-555555555555';
  const resNovoProv = await handleAdminProvisionarOperador(
    new Request('http://localhost/api/admin/operadores/provisionar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-gestor-a' },
      body: JSON.stringify({
        operador_id: OP_SEM_AUTH,
        condominio_id: CONDO_A,
        email: 'novo.porteiro@condo.test',
        password: 'SenhaForte123!',
        nome: 'Novo Porteiro Sem Auth'
      })
    }),
    provEnv
  );
  assert.equal(resNovoProv.status, 200);
  const provJson: any = await resNovoProv.json();
  assert.equal(provJson.acao, 'criado');
  assert.equal(provJson.operador_vinculado, true);
  assert.equal(provJson.auth_user_id, 'bbbb5555-5555-4555-8555-555555555555');
  assert.equal(dbPatches.length, 1);
  assert.equal(dbPatches[0].id, OP_SEM_AUTH);
  assert.equal(dbPatches[0].body.auth_user_id, 'bbbb5555-5555-4555-8555-555555555555');
  assert.equal(operadoresDb.find(o => o.id === OP_SEM_AUTH)?.auth_user_id, 'bbbb5555-5555-4555-8555-555555555555');

  // 2. Gestor sem permissão em cadastros.operadores é bloqueado no provisionamento
  const gestorObj = operadoresDb.find(o => o.id === OP_GESTOR_A)! as any;
  gestorObj.permissoes = { cadastros: { visualizar: true, operadores: false, editar_operadores: false } };
  const resSemPermCad = await handleAdminProvisionarOperador(
    new Request('http://localhost/api/admin/operadores/provisionar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-gestor-a' },
      body: JSON.stringify({
        operador_id: OP_ALVO_A,
        condominio_id: CONDO_A,
        email: 'porteiro.a@condo.test',
        password: 'NovaSenha123!'
      })
    }),
    provEnv
  );
  assert.equal(resSemPermCad.status, 403);

  // 3. Porteiro com permissoes restritas é barrado em OCR, Controle de Acesso (QR), /api/cache/query e /api/cache/warmup
  const permissoesRestritas = {
    encomendas: { visualizar: true, criar: false, entrada_lote: false, triagem: false },
    controle_acesso: { visualizar: true, liberar_entrada: false },
    custodia: { visualizar: false },
    chaves: { visualizar: false },
    moradores: { visualizar: true }
  };

  const hojeBr = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(new Date());

  const passeUnicoConcorrente = {
    id: 'cccc3333-3333-4333-8333-333333333333',
    token: 'PASS-RACE-0002',
    condominio_id: CONDO_A,
    morador_nome: 'João',
    unidade_bloco: 'A - 101',
    visitante_nome: 'Visitante Concorrente',
    tipo: 'visitante',
    data_validade: hojeBr,
    hora_inicio: '00:00',
    hora_fim: '23:59',
    max_usos: 1,
    usos_realizados: 0,
    status: 'valido'
  };

  let operadorPermissoesAtuais: any = permissoesRestritas;
  const mockFetchPerm: typeof fetch = async (input: any, init?: any) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    const method = (init?.method || 'GET').toUpperCase();

    if (url.pathname === '/auth/v1/user') {
      return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'porteiro.a@condo.test' }), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operadores') {
      return new Response(JSON.stringify([{
        id: OP_ALVO_A,
        nome: 'Porteiro Alpha',
        login: 'porteiro.a',
        email: 'porteiro.a@condo.test',
        perfil: 'operador',
        nivel_acesso: 3,
        condominio_id: CONDO_A,
        acesso_global_condominios: false,
        ativo: true,
        auth_user_id: AUTH_ALVO_A,
        permissoes: operadorPermissoesAtuais
      }]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/operador_condominios') {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/rpc/validar_e_consumir_passe_qr') {
      return new Response(JSON.stringify({ code: 'PGRST202' }), { status: 404 });
    }
    if (url.pathname === '/rest/v1/passes_virtuais_qr' && method === 'GET') {
      return new Response(JSON.stringify([{ ...passeUnicoConcorrente }]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/passes_virtuais_qr' && method === 'PATCH') {
      const usosEsp = Number((url.searchParams.get('usos_realizados') || '').replace('eq.', ''));
      const statusEsp = (url.searchParams.get('status') || '').replace('eq.', '');
      if (passeUnicoConcorrente.usos_realizados === usosEsp && passeUnicoConcorrente.status === statusEsp) {
        const b = JSON.parse(String(init.body || '{}'));
        passeUnicoConcorrente.usos_realizados = b.usos_realizados;
        passeUnicoConcorrente.status = b.status;
        return new Response(JSON.stringify([{ ...passeUnicoConcorrente }]), { status: 200 });
      }
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.pathname === '/rest/v1/registros_acesso' && method === 'POST') {
      return new Response(JSON.stringify([{ id: 'rrrr2222-2222-4222-8222-222222222222', condominio_id: CONDO_A }]), { status: 201 });
    }
    if (['/rest/v1/moradores', '/rest/v1/entregadores', '/rest/v1/bancada_volumes'].includes(url.pathname)) {
      return new Response(JSON.stringify([{ id: 'row-1', condominio_id: CONDO_A }]), { status: 200 });
    }
    return new Response(JSON.stringify({}), { status: 404 });
  };

  const envPerm: any = {
    SUPABASE_URL: 'https://mock.supabase.co',
    SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
    SUPABASE_SERVICE_ROLE_KEY: 'mock_service_role_key_12345678901234567890',
    GEMINI_API_KEY: 'mock-gemini-key',
    __fetchImpl: mockFetchPerm
  };

  const resOcrNegado = await handleOcrEtiqueta(
    new Request('http://localhost/api/ocr-etiqueta', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ imagemBase64: 'data:image/jpeg;base64,/9j/4AAQ' })
    }),
    envPerm
  );
  assert.equal(resOcrNegado.status, 403);

  const resQrLeitura = await handleValidarPasseQR(
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ condominioId: CONDO_A, token: 'PASS-RACE-0002', consumir: false })
    }),
    envPerm
  );
  assert.equal(resQrLeitura.status, 200);

  const resQrConsumoNegado = await handleValidarPasseQR(
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ condominioId: CONDO_A, token: 'PASS-RACE-0002', consumir: true })
    }),
    envPerm
  );
  assert.equal(resQrConsumoNegado.status, 403);

  const resCacheCustodiaNegado = await handleCacheQuery(
    new Request('http://localhost/api/cache/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ table: 'custodia', condominioId: CONDO_A })
    }),
    envPerm
  );
  assert.equal(resCacheCustodiaNegado.status, 403);

  const resCacheMoradoresOk = await handleCacheQuery(
    new Request('http://localhost/api/cache/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ table: 'moradores', condominioId: CONDO_A })
    }),
    envPerm
  );
  assert.equal(resCacheMoradoresOk.status, 200);

  const resWarmupParcial = await handleCacheWarmup(
    new Request('http://localhost/api/cache/warmup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ condominioId: CONDO_A })
    }),
    envPerm
  );
  assert.equal(resWarmupParcial.status, 200);
  const warmupJson: any = await resWarmupParcial.json();
  assert.equal(warmupJson.tabelasAquecidas.find((t: any) => t.table === 'chaves')?.status, 'negado');
  assert.equal(warmupJson.tabelasAquecidas.find((t: any) => t.table === 'moradores')?.status, 'ok');

  // Chamada anônima ao QR é rejeitada com 401
  const resQrAnon = await handleValidarPasseQR(
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ condominioId: CONDO_A, token: 'PASS-RACE-0002', consumir: true })
    }),
    envPerm
  );
  assert.equal(resQrAnon.status, 401);

  // Libera permissão de controle_acesso para testar exatamente 2 chamadas simultâneas com max_usos = 1
  operadorPermissoesAtuais = { controle_acesso: { visualizar: true, liberar_entrada: true } };
  const makeRaceReq = () =>
    new Request('http://localhost/api/controle-acesso/validar-passe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer jwt-porteiro-a' },
      body: JSON.stringify({ condominioId: CONDO_A, token: 'PASS-RACE-0002', consumir: true })
    });
  const [race1, race2] = await Promise.all([
    handleValidarPasseQR(makeRaceReq(), envPerm),
    handleValidarPasseQR(makeRaceReq(), envPerm)
  ]);
  assert.equal([race1.status, race2.status].filter(s => s === 200).length, 1);
  assert.equal([race1.status, race2.status].filter(s => s === 400 || s === 409).length, 1);
  assert.equal(passeUnicoConcorrente.usos_realizados, 1);
});

test('[Segunda Rodada SQL & Frontend] Sem bypass current_user NOT IN, trigger QR SECURITY INVOKER, proteção auth_email e migração 11/12 seguras', () => {
  const sql05 = fs.readFileSync(path.resolve('supabase/sql/05_FUNCOES_AUTORIZACAO.sql'), 'utf8');
  const sql05b = fs.readFileSync(path.resolve('supabase/sql/05B_FUNCOES_PASSE_QR.sql'), 'utf8');
  const sql06 = fs.readFileSync(path.resolve('supabase/sql/06_RLS_TABELAS_MULTI_TENANT.sql'), 'utf8');
  const sql07 = fs.readFileSync(path.resolve('supabase/sql/07_STORAGE_PRIVADO_POLICIES.sql'), 'utf8');
  const sql11 = fs.readFileSync(path.resolve('supabase/sql/11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql'), 'utf8');
  const sql12 = fs.readFileSync(path.resolve('supabase/sql/12_AUDITORIA_FINAL_SEGURANCA.sql'), 'utf8');
  const cadastrosCode = fs.readFileSync(path.resolve('src/pages/Cadastros.tsx'), 'utf8');

  // 1. Zero bypass current_user NOT IN em 05B e 11; exige service_role quando auth.uid() IS NULL
  for (const [nome, conteudo] of [['05B', sql05b], ['11', sql11]] as const) {
    assert.equal(/current_user\s+NOT\s+IN\s*\(\s*'postgres'/i.test(conteudo), false, `${nome}: não pode conter bypass current_user NOT IN`);
    assert.ok(/v_jwt_role\s*(?:=|<>)\s*'service_role'/.test(conteudo), `${nome}: deve validar service_role no JWT`);
    assert.ok(conteudo.includes('operador_tem_permissao_modulo'), `${nome}: validar_e_consumir_passe_qr deve exigir permissão funcional`);
    assert.ok(conteudo.includes('porttohub_internal.passe_qr_tx_autorizacao'), `${nome}: RPC deve usar tabela interna transacional`);
    assert.equal(conteudo.includes("porttohub.rpc_passe_qr_consumo"), false, `${nome}: não deve mais usar GUC de sessão porttohub.rpc_passe_qr_consumo`);
  }

  // 2. 06 e 11 possuem proteger_campos_passe_qr SECURITY INVOKER, permissões por módulo e integridade cross-condo em tabelas filhas
  for (const [nome, conteudo] of [['06', sql06], ['11', sql11]] as const) {
    const qrTrigFn = conteudo.split('CREATE OR REPLACE FUNCTION public.proteger_campos_passe_qr()')[1]
      .split('REVOKE ALL ON FUNCTION public.proteger_campos_passe_qr()')[0]
      .replace(/--[^\n]*/g, '');
    assert.equal(qrTrigFn.includes('SECURITY DEFINER'), false, `${nome}: proteger_campos_passe_qr deve ser SECURITY INVOKER`);
    assert.ok(qrTrigFn.includes('SECURITY INVOKER'), `${nome}: proteger_campos_passe_qr deve usar SECURITY INVOKER`);
    assert.ok(qrTrigFn.includes('COALESCE(NEW.usos_realizados, 0) IS DISTINCT FROM COALESCE(OLD.usos_realizados, 0)'), `${nome}: deve proteger usos_realizados`);
    assert.ok(conteudo.includes('trg_proteger_campos_passe_qr'), `${nome}: trigger de passes QR ausente`);
    assert.ok(conteudo.includes('operador_tem_permissao_modulo'), `${nome}: RLS deve validar operador_tem_permissao_modulo`);
    assert.ok(conteudo.includes('encomendas_itens_insert'), `${nome}: policy de encomendas_itens deve validar FK do mesmo condomínio`);
    assert.ok(conteudo.includes('rondas_registros_insert'), `${nome}: policy de rondas_registros deve validar FK de ponto do mesmo condomínio`);
  }

  // 3. operador_auth_email_corresponde bloqueia consulta arbitrária a auth.users por authenticated
  for (const [nome, conteudo] of [['05', sql05], ['11', sql11]] as const) {
    const fnEmail = conteudo.split('CREATE OR REPLACE FUNCTION public.operador_auth_email_corresponde')[1]
      .split('REVOKE ALL ON FUNCTION public.operador_auth_email_corresponde')[0];
    assert.ok(
      fnEmail.includes('p_auth_user_id IS DISTINCT FROM auth.uid()') || fnEmail.includes('p_auth_user_id = auth.uid()'),
      `${nome}: operador_auth_email_corresponde deve restringir a próprio uid ou service_role`
    );
    assert.ok(
      /v_jwt_role\s*(?:=|<>)\s*'service_role'/.test(fnEmail),
      `${nome}: operador_auth_email_corresponde deve aceitar service_role`
    );
    assert.ok(
      /CREATE OR REPLACE FUNCTION public\.operador_tem_permissao_modulo\(\s*p_condominio_id TEXT/.test(conteudo),
      `${nome}: função operador_tem_permissao_modulo(TEXT) ausente`
    );
  }

  // 4. Storage 07 e 11 exigem operador ativo nas 4 políticas condominios/ além de operadores/
  assert.equal((sql07.match(/public\.operador_atual_id\(\) IS NOT NULL/g) || []).length >= 8, true);
  assert.equal((sql11.match(/public\.operador_atual_id\(\) IS NOT NULL/g) || []).length >= 8, true);

  // 5. Migração 11 faz pré-auditoria de pg_policies e só remove policies das 35 tabelas explícitas (todas_tabelas)
  assert.ok(sql11.includes('Pre-auditoria pg_policies'));
  assert.ok(sql11.includes('FOREACH tbl IN ARRAY todas_tabelas'));
  assert.ok(sql11.includes("WHERE schemaname = 'public' AND tablename = tbl"));

  // 6. Auditoria 12 é 100% read-only e documenta escopo SQL vs backend /api/*
  const sql12NoComments = sql12.replace(/--[^\n]*/g, '').replace(/'[^']*'/g, "''");
  assert.equal(/\b(CREATE|DROP|ALTER|INSERT|UPDATE|DELETE|TRUNCATE)\b/i.test(sql12NoComments), false, '12 deve ser exclusivamente read-only');
  assert.ok(sql12.includes('pg_get_functiondef'));
  assert.ok(sql12.includes('trg_proteger_campos_passe_qr'));
  assert.ok(sql12.includes('/api/*'));

  // 7. Cadastros.tsx insere novo operador com auth_user_id: null antes de provisionar via backend
  assert.ok(cadastrosCode.includes('auth_user_id: null'));
  assert.ok(cadastrosCode.includes('chamarProvisionamentoBackend(opIdSalvo)'));
});

test('[Terceira Rodada SQL] Escopo restrito às 35 tabelas/sequências oficiais, autoria historico_absoluto/registros_acesso, schema interno QR e Auditoria 12 padronizada', () => {
  const sql05 = fs.readFileSync(path.resolve('supabase/sql/05_FUNCOES_AUTORIZACAO.sql'), 'utf8');
  const sql05b = fs.readFileSync(path.resolve('supabase/sql/05B_FUNCOES_PASSE_QR.sql'), 'utf8');
  const sql06 = fs.readFileSync(path.resolve('supabase/sql/06_RLS_TABELAS_MULTI_TENANT.sql'), 'utf8');
  const sql11 = fs.readFileSync(path.resolve('supabase/sql/11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql'), 'utf8');
  const sql12 = fs.readFileSync(path.resolve('supabase/sql/12_AUDITORIA_FINAL_SEGURANCA.sql'), 'utf8');
  const auditoriaTs = fs.readFileSync(path.resolve('src/services/auditoriaService.ts'), 'utf8');
  const permissoesTs = fs.readFileSync(path.resolve('src/services/permissoesService.ts'), 'utf8');
  const readmeMd = fs.readFileSync(path.resolve('README.md'), 'utf8');

  // 1. 06 e 11 nunca iteram cegamente sobre todas as tabelas/sequências de public; filtram por todas_tabelas (35) e pg_depend
  for (const [nome, conteudo] of [['06', sql06], ['11', sql11]] as const) {
    assert.equal(/FOR\s+r\s+IN\s+SELECT\s+tablename\s+FROM\s+pg_tables\s+WHERE\s+schemaname\s*=\s*'public'\s+LOOP/i.test(conteudo), false, `${nome}: não pode iterar cegamente em pg_tables`);
    assert.equal(/REVOKE\s+ALL\s+ON\s+ALL\s+TABLES\s+IN\s+SCHEMA\s+public/i.test(conteudo), false, `${nome}: não pode revogar ALL TABLES IN SCHEMA public (deve preservar tabelas extras)`);
    assert.equal(/REVOKE\s+ALL\s+ON\s+ALL\s+SEQUENCES\s+IN\s+SCHEMA\s+public/i.test(conteudo), false, `${nome}: não pode revogar ALL SEQUENCES IN SCHEMA public (deve preservar sequências extras)`);
    assert.ok(conteudo.includes('pg_depend'), `${nome}: deve identificar sequências oficiais via pg_depend`);
    assert.ok(
      conteudo.includes('NOT (c.relname = ANY(todas_tabelas))') ||
      conteudo.includes('NOT (t.tablename = ANY(todas_tabelas))'),
      `${nome}: pré-auditoria deve reportar tabelas extras preservadas`
    );
    assert.ok(conteudo.includes('trg_proteger_autoria_historico_absoluto'), `${nome}: trigger de autoria em historico_absoluto ausente`);
    assert.ok(conteudo.includes('trg_proteger_autoria_registros_acesso'), `${nome}: trigger de autoria em registros_acesso ausente`);
    assert.ok(conteudo.includes('porttohub_internal.passe_qr_tx_autorizacao'), `${nome}: marcador transacional interno QR ausente`);

    // Triggers de autoria precisam ser SECURITY INVOKER
    const trigHist = conteudo.split('CREATE OR REPLACE FUNCTION public.proteger_autoria_historico_absoluto()')[1]
      .split('REVOKE ALL ON FUNCTION public.proteger_autoria_historico_absoluto()')[0]
      .replace(/--[^\n]*/g, '');
    const trigReg = conteudo.split('CREATE OR REPLACE FUNCTION public.proteger_autoria_registros_acesso()')[1]
      .split('REVOKE ALL ON FUNCTION public.proteger_autoria_registros_acesso()')[0]
      .replace(/--[^\n]*/g, '');
    assert.ok(trigHist.includes('SECURITY INVOKER') && !trigHist.includes('SECURITY DEFINER'), `${nome}: proteger_autoria_historico_absoluto deve ser SECURITY INVOKER`);
    assert.ok(trigReg.includes('SECURITY INVOKER') && !trigReg.includes('SECURITY DEFINER'), `${nome}: proteger_autoria_registros_acesso deve ser SECURITY INVOKER`);
  }

  // 2. Unificação configuracoes.niveis_acesso em 05 e 11
  for (const [nome, conteudo] of [['05', sql05], ['11', sql11]] as const) {
    assert.ok(conteudo.includes('FROM public.configuracoes c'), `${nome}: operador_tem_permissao_modulo deve consultar configuracoes.niveis_acesso`);
    assert.ok(conteudo.includes('v_eh_nivel_custom'), `${nome}: operador_tem_permissao_modulo deve distinguir nível personalizado e falhar fechado`);
  }

  // 3. Schema privado porttohub_internal em 05B e 11 revogado de PUBLIC, anon e authenticated
  for (const [nome, conteudo] of [['05B', sql05b], ['11', sql11]] as const) {
    assert.ok(conteudo.includes('CREATE SCHEMA IF NOT EXISTS porttohub_internal'), `${nome}: deve criar schema privado porttohub_internal`);
    assert.ok(conteudo.includes('REVOKE ALL ON SCHEMA porttohub_internal FROM PUBLIC, anon, authenticated'), `${nome}: deve isolar schema porttohub_internal`);
    assert.ok(conteudo.includes('REVOKE ALL ON TABLE porttohub_internal.passe_qr_tx_autorizacao FROM PUBLIC, anon, authenticated'), `${nome}: deve isolar tabela passe_qr_tx_autorizacao`);
  }

  // 4. Auditoria 12: somente status oficiais ('OK', 'ATENÇÃO', 'FALHA', 'NÃO TESTADO') + VERIFICAÇÃO ESTRUTURAL
  assert.equal(sql12.includes("'ATENCAO'"), false, '12 deve usar grafia oficial ATENÇÃO');
  assert.ok(sql12.includes('VERIFICAÇÃO ESTRUTURAL'));
  assert.ok(sql12.includes('EXTRA_PRESERVADA'));
  assert.ok(sql12.includes('trg_proteger_autoria_historico_absoluto'));
  assert.ok(sql12.includes('trg_proteger_autoria_registros_acesso'));
  assert.ok(sql12.includes('passe_qr_tx_autorizacao'));

  // 5. auditoriaService.ts não possui FOR ALL e permissoesService.ts não contém ?? true
  assert.equal(/\bFOR\s+ALL\b/i.test(auditoriaTs), false, 'auditoriaService.ts não deve gerar política FOR ALL');
  assert.equal(permissoesTs.includes('?? true'), false, 'permissoesService.ts não deve conter fallbacks permissivos ?? true');
  assert.ok(readmeMd.includes('porttohub_internal.passe_qr_tx_autorizacao'));
  assert.ok(readmeMd.includes('EXTRA') || readmeMd.includes('tabelas extras'));
});

test('[Terceira Rodada Matriz Unificada] Nível personalizado em configuracoes.niveis_acesso (Backend + Frontend) e fail-closed sem vazamento', async () => {
  const { authenticateRequest, temPermissaoModuloBackend } = await import('../src/server/authMiddleware.ts');
  const permissoesSvc = await import('../src/services/permissoesService.ts');

  const customNiveis = [
    {
      id: 'custom_portaria_audit',
      nome: 'Portaria Auditoria Restrita',
      condominio_id: CONDO_A,
      padrao_sistema: false,
      permissoes: {
        encomendas: { visualizar: true, criar: false, editar: false, excluir: false },
        custodia: { visualizar: false, receber: false, baixar: false, excluir: false },
        bancada: { visualizar: true, lancar: true, baixa: false, zerar: false }
      }
    }
  ];

  // A. Backend respeita configuracoes.niveis_acesso do condomínio alvo
  const { env } = (() => {
    const customFetch: typeof fetch = async (input: any) => {
      const url = new URL(typeof input === 'string' ? input : input.url);
      if (url.pathname === '/auth/v1/user') {
        return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'custom.op@condo.test' }), { status: 200 });
      }
      if (url.pathname === '/rest/v1/operadores') {
        return new Response(JSON.stringify([{
          id: OP_ALVO_A,
          nome: 'Operador Customizado',
          login: 'custom.op',
          email: 'custom.op@condo.test',
          perfil: 'operador',
          nivel_acesso: 3,
          nivel_acesso_custom_id: 'custom_portaria_audit',
          condominio_id: CONDO_A,
          acesso_global_condominios: false,
          ativo: true,
          auth_user_id: AUTH_ALVO_A,
          permissoes: { bancada: { baixa: true } }
        }]), { status: 200 });
      }
      if (url.pathname === '/rest/v1/operador_condominios') {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      if (url.pathname === '/rest/v1/configuracoes') {
        return new Response(JSON.stringify([{ condominio_id: CONDO_A, niveis_acesso: customNiveis }]), { status: 200 });
      }
      return new Response(JSON.stringify([]), { status: 200 });
    };
    return {
      env: {
        SUPABASE_URL: 'https://mock.supabase.co',
        SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
        __fetchImpl: customFetch
      } as any
    };
  })();

  const authRes = await authenticateRequest(
    new Request('http://localhost/api/cache/stats', { headers: { Authorization: 'Bearer jwt-custom' } }),
    env
  );
  assert.equal(authRes.ok, true);
  if (authRes.ok) {
    assert.equal(temPermissaoModuloBackend(authRes.context, 'encomendas', 'visualizar', CONDO_A), true);
    assert.equal(temPermissaoModuloBackend(authRes.context, 'encomendas', 'criar', CONDO_A), false);
    assert.equal(temPermissaoModuloBackend(authRes.context, 'custodia', 'visualizar', CONDO_A), false);
    assert.equal(temPermissaoModuloBackend(authRes.context, 'chaves', 'visualizar', CONDO_A), false);
    assert.equal(temPermissaoModuloBackend(authRes.context, 'bancada', 'baixa', CONDO_A), true); // override explícito

    // Nível customizado inexistente falha fechado
    const ctxInexistente = {
      ...authRes.context,
      operador: { ...authRes.context.operador, nivel_acesso_custom_id: 'custom_nao_existe', permissoes: {} }
    };
    assert.equal(temPermissaoModuloBackend(ctxInexistente, 'encomendas', 'visualizar', CONDO_A), false);
    assert.equal(temPermissaoModuloBackend(ctxInexistente, 'bancada', 'baixa', CONDO_A), false);
  }

  // B. Frontend permissoesService.ts resolve custom level, overrides esparsos e falha fechado sem fallback localStorage
  const origStorage = (globalThis as any).localStorage;
  const store = new Map<string, string>();
  (globalThis as any).localStorage = {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => { store.set(k, String(v)); },
    removeItem: (k: string) => { store.delete(k); }
  };

  try {
    permissoesSvc.limparCacheNiveisAcesso();
    permissoesSvc.salvarNiveisLocal([
      ...permissoesSvc.NIVEIS_PADRAO,
      customNiveis[0] as any
    ]);

    const opCustom = {
      id: OP_ALVO_A,
      login: 'custom.op',
      perfil: 'operador',
      nivel_acesso: 3,
      nivel_acesso_custom_id: 'custom_portaria_audit',
      condominio_id: CONDO_A,
      acesso_global_condominios: false,
      ativo: true,
      permissoes: { bancada: { baixa: true } }
    };

    assert.equal(permissoesSvc.verificarPermissao(opCustom, 'encomendas', 'visualizar'), true);
    assert.equal(permissoesSvc.verificarPermissao(opCustom, 'encomendas', 'criar'), false);
    assert.equal(permissoesSvc.verificarPermissao(opCustom, 'custodia', 'visualizar'), false);
    assert.equal(permissoesSvc.verificarPermissao(opCustom, 'chaves', 'visualizar'), false);
    assert.equal(permissoesSvc.verificarPermissao(opCustom, 'bancada', 'baixa'), true);

    // Extrai somente overrides esparsos sem congelar matriz inteira
    const completas = permissoesSvc.obterPermissoesOperador(opCustom);
    const overrides = permissoesSvc.extrairOverridesOperador(completas, 'custom_portaria_audit', undefined, 'TODAS');
    assert.equal(overrides.encomendas, undefined);
    assert.equal(overrides.bancada?.baixa, true);

    // Chave legada em localStorage não pode conceder privilégios
    store.set(`porttohub_operador_permissoes_${OP_ALVO_A}`, JSON.stringify({ custodia: { visualizar: true, excluir: true } }));
    const opSemPermDb = { ...opCustom, permissoes: {} };
    assert.equal(permissoesSvc.verificarPermissao(opSemPermDb, 'custodia', 'visualizar'), false);

    // Nível customizado inexistente falha fechado mesmo para overrides parciais
    const opCustomInexistente = { ...opCustom, nivel_acesso_custom_id: 'custom_removido' };
    assert.equal(permissoesSvc.verificarPermissao(opCustomInexistente, 'bancada', 'baixa'), false);
    assert.equal(permissoesSvc.verificarPermissao(opCustomInexistente, 'encomendas', 'visualizar'), false);

    permissoesSvc.limparCacheNiveisAcesso();
  } finally {
    (globalThis as any).localStorage = origStorage;
  }
});

test('[Migração 11 Final - Regressão Classificação] Operadores com nivel_acesso 0/1 ou nivel_acesso_custom_id nivel_0/nivel_1 NUNCA viram administradores', async () => {
  const { authenticateRequest, temPermissaoModuloBackend } = await import('../src/server/authMiddleware.ts');
  const permissoesSvc = await import('../src/services/permissoesService.ts');

  const casosOperador = [
    { rotulo: 'operador + nivel_acesso: 0', perfil: 'operador', nivel_acesso: 0, nivel_acesso_custom_id: null, acesso_global_condominios: false },
    { rotulo: 'operador + nivel_acesso: 1', perfil: 'operador', nivel_acesso: 1, nivel_acesso_custom_id: null, acesso_global_condominios: false },
    { rotulo: 'operador + custom nivel_0', perfil: 'operador', nivel_acesso: 3, nivel_acesso_custom_id: 'nivel_0', acesso_global_condominios: false },
    { rotulo: 'operador + custom nivel_1', perfil: 'operador', nivel_acesso: 3, nivel_acesso_custom_id: 'nivel_1', acesso_global_condominios: false },
    { rotulo: 'operador + acesso_global_condominios=true indevido', perfil: 'operador', nivel_acesso: 1, nivel_acesso_custom_id: 'nivel_1', acesso_global_condominios: true },
    { rotulo: 'supervisor + nivel_acesso: 0/1 + custom nivel_0', perfil: 'supervisor', nivel_acesso: 0, nivel_acesso_custom_id: 'nivel_0', acesso_global_condominios: true }
  ];

  const origStorage = (globalThis as any).localStorage;
  const store = new Map<string, string>();
  (globalThis as any).localStorage = {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => { store.set(k, String(v)); },
    removeItem: (k: string) => { store.delete(k); }
  };

  try {
    permissoesSvc.limparCacheNiveisAcesso();

    // Custom level tentando conceder ações administrativas a um operador comum
    const nivelCustomMalicioso = {
      id: 'custom_portaria_admin_tentativa',
      nome: 'Tentativa Admin Custom',
      condominio_id: CONDO_A,
      padrao_sistema: false,
      permissoes: {
        encomendas: { visualizar: true, criar: true, editar: false, excluir: false },
        cadastros: {
          visualizar: true,
          moradores: true,
          operadores: true,
          editar_operadores: true,
          configurar_condominio: true,
          condominios: true,
          gerenciar_niveis: true
        },
        configuracoes: {
          visualizar: true,
          editar: true,
          auditoria: true,
          limpar_dados: true
        },
        historico_absoluto: {
          visualizar: true,
          exportar: true,
          limpar_dados: true
        }
      }
    };

    permissoesSvc.salvarNiveisLocal([...permissoesSvc.NIVEIS_PADRAO, nivelCustomMalicioso as any]);

    for (const c of casosOperador) {
      const opMock = {
        id: OP_ALVO_A,
        nome: c.rotulo,
        login: 'op.teste',
        perfil: c.perfil,
        nivel_acesso: c.nivel_acesso,
        nivel_acesso_custom_id: c.nivel_acesso_custom_id,
        condominio_id: CONDO_A,
        acesso_global_condominios: c.acesso_global_condominios,
        ativo: true,
        permissoes: {
          cadastros: { operadores: true, editar_operadores: true, configurar_condominio: true, condominios: true },
          configuracoes: { visualizar: true, editar: true }
        }
      };

      // 1. autorizacaoService.ts
      assert.equal(temAcessoGlobalExplicito(opMock), false, `${c.rotulo}: não pode ter acesso global`);
      assert.equal(ehAdminCondominio(opMock), false, `${c.rotulo}: não pode ser admin_condominio`);
      assert.equal(podeGerenciarOperadoresNoCondominio(opMock, CONDO_A), false, `${c.rotulo}: não pode gerenciar operadores`);
      assert.equal(normalizarPerfilOperador(opMock), c.perfil === 'supervisor' ? 'supervisor' : 'operador', `${c.rotulo}: perfil normalizado incorreto`);

      // 2. permissoesService.ts (frontend)
      const nivelEfetivo = permissoesSvc.extrairIdNivel(opMock);
      assert.notEqual(nivelEfetivo, 'nivel_0', `${c.rotulo}: nivel efetivo não pode ser nivel_0`);
      assert.notEqual(nivelEfetivo, 'nivel_1', `${c.rotulo}: nivel efetivo não pode ser nivel_1`);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'cadastros', 'operadores'), false, `${c.rotulo}: frontend não deve liberar cadastros.operadores`);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'cadastros', 'editar_operadores'), false, `${c.rotulo}: frontend não deve liberar cadastros.editar_operadores`);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'cadastros', 'configurar_condominio'), false, `${c.rotulo}: frontend não deve liberar cadastros.configurar_condominio`);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'cadastros', 'condominios'), false, `${c.rotulo}: frontend não deve liberar cadastros.condominios`);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'cadastros', 'gerenciar_niveis'), false, `${c.rotulo}: frontend não deve liberar cadastros.gerenciar_niveis`);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'configuracoes', 'editar'), false, `${c.rotulo}: frontend não deve liberar configuracoes.editar`);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'encomendas', 'visualizar'), true, `${c.rotulo}: mantém permissões operacionais padrão`);

      // 3. Backend authMiddleware.ts
      const customFetch: typeof fetch = async (input: any) => {
        const url = new URL(typeof input === 'string' ? input : input.url);
        if (url.pathname === '/auth/v1/user') {
          return new Response(JSON.stringify({ id: AUTH_ALVO_A, email: 'op.teste@condo.test' }), { status: 200 });
        }
        if (url.pathname === '/rest/v1/operadores') {
          return new Response(JSON.stringify([{ ...opMock, auth_user_id: AUTH_ALVO_A }]), { status: 200 });
        }
        if (url.pathname === '/rest/v1/operador_condominios') {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (url.pathname === '/rest/v1/configuracoes') {
          return new Response(JSON.stringify([{ condominio_id: CONDO_A, niveis_acesso: [nivelCustomMalicioso] }]), { status: 200 });
        }
        return new Response(JSON.stringify([]), { status: 200 });
      };

      const authRes = await authenticateRequest(
        new Request('http://localhost/api/cache/stats', { headers: { Authorization: 'Bearer jwt-op' } }),
        {
          SUPABASE_URL: 'https://mock.supabase.co',
          SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
          __fetchImpl: customFetch
        } as any
      );
      assert.equal(authRes.ok, true);
      if (authRes.ok) {
        assert.equal(authRes.context.eAdminGlobal, false, `${c.rotulo}: backend eAdminGlobal deve ser false`);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'cadastros', 'operadores', CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'cadastros', 'editar_operadores', CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'cadastros', 'configurar_condominio', CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'cadastros', 'condominios', CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'cadastros', 'gerenciar_niveis', CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'configuracoes', 'editar', CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'encomendas', 'visualizar', CONDO_A), true);
      }
    }

    // Operador com custom level malicioso continua bloqueado nas ações administrativas, mantendo encomendas.criar
    const opCustomTentativa = {
      id: OP_ALVO_A,
      nome: 'Operador Custom Tentativa Admin',
      login: 'op.custom.tentativa',
      perfil: 'operador',
      nivel_acesso: 3,
      nivel_acesso_custom_id: 'custom_portaria_admin_tentativa',
      condominio_id: CONDO_A,
      acesso_global_condominios: false,
      ativo: true,
      permissoes: {}
    };
    assert.equal(permissoesSvc.verificarPermissao(opCustomTentativa, 'encomendas', 'criar'), true);
    assert.equal(permissoesSvc.verificarPermissao(opCustomTentativa, 'cadastros', 'operadores'), false);
    assert.equal(permissoesSvc.verificarPermissao(opCustomTentativa, 'cadastros', 'configurar_condominio'), false);
    assert.equal(permissoesSvc.verificarPermissao(opCustomTentativa, 'configuracoes', 'limpar_dados'), false);
    assert.equal(permissoesSvc.verificarPermissao(opCustomTentativa, 'historico_absoluto', 'limpar_dados'), false);

    // admin_condominio somente administra no condomínio principal (CONDO_A), não no secundário (CONDO_B)
    const adminCondo = {
      id: OP_GESTOR_A,
      nome: 'Admin Condo A',
      login: 'admin.condo.a',
      perfil: 'admin_condominio',
      nivel_acesso: 1,
      nivel_acesso_custom_id: 'nivel_1',
      condominio_id: CONDO_A,
      acesso_global_condominios: false,
      ativo: true,
      permissoes: {}
    };
    assert.equal(podeGerenciarOperadoresNoCondominio(adminCondo, CONDO_A), true);
    assert.equal(podeGerenciarOperadoresNoCondominio(adminCondo, CONDO_B), false);

    permissoesSvc.limparCacheNiveisAcesso();
  } finally {
    (globalThis as any).localStorage = origStorage;
  }
});

test('[Migração 11 Final - Regressão Histórico Absoluto] Validação de permissão por (modulo, acao), bloqueio sem privilégio e rollback de cache', async () => {
  const { validarPermissaoAuditoriaLocal, registrarAtividade, obterHistoricoCacheLocal } = await import('../src/services/auditoriaService.ts');
  const permissoesSvc = await import('../src/services/permissoesService.ts');

  const origStorage = (globalThis as any).localStorage;
  const store = new Map<string, string>();
  (globalThis as any).localStorage = {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => { store.set(k, String(v)); },
    removeItem: (k: string) => { store.delete(k); }
  };

  try {
    permissoesSvc.limparCacheNiveisAcesso();

    const operadorComum = {
      id: OP_ALVO_A,
      nome: 'Porteiro Padrão',
      login: 'porteiro.a',
      perfil: 'operador',
      nivel_acesso: 1, // Mesmo com nível legado 1, continua operador comum!
      nivel_acesso_custom_id: 'nivel_1',
      condominio_id: CONDO_A,
      acesso_global_condominios: false,
      ativo: true,
      permissoes: {}
    };

    const sindicoMock = {
      id: 'aaaa5555-5555-4555-8555-555555555555',
      nome: 'Síndico A',
      login: 'sindico.a',
      perfil: 'sindico',
      nivel_acesso: 4,
      nivel_acesso_custom_id: 'nivel_4',
      condominio_id: CONDO_A,
      acesso_global_condominios: false,
      ativo: true,
      permissoes: {}
    };

    // Pares operacionais legítimos do operador comum
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'Sistema', 'LOGIN', CONDO_A), true);
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'encomendas', 'CRIAR', CONDO_A), true);
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'custodia', 'receber', CONDO_A), true);
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'Controle de Acesso', 'ENTRADA_REGISTRADA', CONDO_A), true);
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'lembretes_portaria', 'LEMBRETE_CIENTE', CONDO_A), true);

    // Pares administrativos/não autorizados/inventados devem ser bloqueados
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'Limpeza de Dados', 'LIMPEZA_PERIODO', CONDO_A), false);
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'Sistema', 'MUTE_ALERTA', CONDO_A), false);
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'custodia', 'excluir', CONDO_A), false);
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'cadastros', 'operadores', CONDO_A), false);
    assert.equal(validarPermissaoAuditoriaLocal(operadorComum, 'modulo_inventado', 'acao_fake', CONDO_A), false);

    // Síndico pode registrar nova ocorrência de síndico, mas NÃO pode limpar dados ou registrar exclusão de custódia
    assert.equal(validarPermissaoAuditoriaLocal(sindicoMock, 'Ocorrências', 'NOVA_OCORRENCIA_SINDICO', CONDO_A), true);
    assert.equal(validarPermissaoAuditoriaLocal(sindicoMock, 'Limpeza de Dados', 'LIMPEZA_PERIODO', CONDO_A), false);
    assert.equal(validarPermissaoAuditoriaLocal(sindicoMock, 'custodia', 'excluir', CONDO_A), false);

    // registrarAtividade bloqueia antes de gravar no cache local quando sem permissão
    await assert.rejects(
      () => registrarAtividade({
        modulo: 'Limpeza de Dados',
        acao: 'LIMPEZA_PERIODO',
        descricao: 'Tentativa indevida de limpeza por operador comum',
        operador: operadorComum,
        condominio_id: CONDO_A
      }),
      /Acesso negado/i
    );
    assert.equal(obterHistoricoCacheLocal().length, 0, 'Tentativa negada não pode persistir no cache local');

    permissoesSvc.limparCacheNiveisAcesso();
  } finally {
    (globalThis as any).localStorage = origStorage;
  }
});

test('[Migração 11 Final - SQL 05/06/11/12] Invariantes estáticos de classificação, proteção de autoria e Auditoria 12 read-only', () => {
  const sql05 = fs.readFileSync(path.resolve('supabase/sql/05_FUNCOES_AUTORIZACAO.sql'), 'utf8');
  const sql06 = fs.readFileSync(path.resolve('supabase/sql/06_RLS_TABELAS_MULTI_TENANT.sql'), 'utf8');
  const sql11 = fs.readFileSync(path.resolve('supabase/sql/11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql'), 'utf8');
  const sql12 = fs.readFileSync(path.resolve('supabase/sql/12_AUDITORIA_FINAL_SEGURANCA.sql'), 'utf8');

  for (const [nome, sql] of [['05', sql05], ['11', sql11]] as const) {
    assert.equal(sql.includes("OR v_nivel_id = 'nivel_1'"), false, `${nome}: não pode promover operador via v_nivel_id = 'nivel_1'`);
    assert.equal(sql.includes('OR v_nivel = 2'), false, `${nome}: não pode promover operador via nivel_acesso = 2`);
    assert.equal(sql.includes('OR v_nivel = 4'), false, `${nome}: não pode classificar síndico via nivel_acesso = 4`);
    assert.ok(sql.includes("lower(trim(COALESCE(o.perfil, ''))) = 'admin_geral'"), `${nome}: acesso global deve exigir perfil = admin_geral`);
    assert.ok(sql.includes('CREATE OR REPLACE FUNCTION public.operador_pode_registrar_auditoria('), `${nome}: deve definir operador_pode_registrar_auditoria`);
    assert.ok(sql.includes('REVOKE ALL ON FUNCTION public.operador_pode_registrar_auditoria(TEXT, TEXT, TEXT) FROM PUBLIC, anon'), `${nome}: deve revogar PUBLIC e anon de operador_pode_registrar_auditoria`);
  }

  for (const [nome, sql] of [['06', sql06], ['11', sql11]] as const) {
    assert.ok(sql.includes('public.operador_pode_registrar_auditoria(NEW.condominio_id::text, NEW.modulo, NEW.acao)'), `${nome}: trigger historico_absoluto deve exigir operador_pode_registrar_auditoria`);
    assert.ok(sql.includes('public.operador_pode_registrar_auditoria(condominio_id::text, modulo, acao)'), `${nome}: RLS INSERT de historico_absoluto deve exigir operador_pode_registrar_auditoria`);
    assert.ok(sql.includes('NEW.operador_id := v_op.id'), `${nome}: trigger deve preservar autoria preenchida pelo banco`);
    assert.ok(sql.includes('NEW.criado_em := NOW()'), `${nome}: trigger deve preservar timestamp preenchido pelo banco`);
  }

  assert.ok(sql12.includes("'operador_pode_registrar_auditoria'"), '12 deve auditar função operador_pode_registrar_auditoria');
  assert.ok(sql12.includes('Consistência de classificação em public.operadores'), '12 deve incluir check 18 de consistência em operadores');
  assert.ok(sql12.includes('VERIFICAÇÃO ESTRUTURAL'));
  // 12 deve ser 100% read-only (sem DDL/DML fora de comentários)
  const sql12SemComentarios = sql12
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/--[^\n]*/g, '')
    .replace(/'[^']*'/g, "''");
  assert.equal(/\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|GRANT|REVOKE|TRUNCATE)\b/i.test(sql12SemComentarios), false, '12 deve ser 100% read-only');
});

test('[Classificação Administrativa Estrita] Apenas admin_geral (ativo + global=true) e admin_condominio (condomínio principal); admin_local/admin/master/desconhecidos bloqueados', async () => {
  const { authenticateRequest, temPermissaoModuloBackend } = await import('../src/server/authMiddleware.ts');
  const permissoesSvc = await import('../src/services/permissoesService.ts');

  const origStorage = (globalThis as any).localStorage;
  const store = new Map<string, string>();
  (globalThis as any).localStorage = {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => { store.set(k, String(v)); },
    removeItem: (k: string) => { store.delete(k); }
  };

  try {
    permissoesSvc.limparCacheNiveisAcesso();

    const testarNoBackend = async (opRow: any, links: string[] = []) => {
      const customFetch: typeof fetch = async (input: any) => {
        const url = new URL(typeof input === 'string' ? input : input.url);
        if (url.pathname === '/auth/v1/user') {
          return new Response(JSON.stringify({ id: opRow.auth_user_id, email: opRow.email }), { status: 200 });
        }
        if (url.pathname === '/rest/v1/operadores') {
          return new Response(JSON.stringify([opRow]), { status: 200 });
        }
        if (url.pathname === '/rest/v1/operador_condominios') {
          return new Response(
            JSON.stringify(links.map(cid => ({ condominio_id: cid, ativo: true }))),
            { status: 200 }
          );
        }
        if (url.pathname === '/rest/v1/configuracoes') {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        return new Response(JSON.stringify([]), { status: 200 });
      };

      return authenticateRequest(
        new Request('http://localhost/api/cache/stats', { headers: { Authorization: 'Bearer jwt-strict-test' } }),
        {
          SUPABASE_URL: 'https://mock.supabase.co',
          SUPABASE_ANON_KEY: 'mock_anon_key_12345678901234567890',
          __fetchImpl: customFetch
        } as any
      );
    };

    // 1. admin_local, admin, master e perfis desconhecidos (mesmo com acesso_global_condominios=true, nivel=0/1 e custom nivel_0/nivel_1)
    for (const perfilInvalido of ['admin_local', 'admin', 'master', 'super_usuario', 'gerente_ti', '', null]) {
      const opMock: any = {
        id: OP_ALVO_A,
        auth_user_id: AUTH_ALVO_A,
        nome: `Teste ${String(perfilInvalido)}`,
        login: 'admin',
        email: 'op@condo.test',
        perfil: perfilInvalido,
        nivel_acesso: 0,
        nivel_acesso_custom_id: 'nivel_0',
        condominio_id: CONDO_A,
        acesso_global_condominios: true,
        eSuperAdminGlobal: true,
        ativo: true,
        permissoes: {
          cadastros: { operadores: true, editar_operadores: true, configurar_condominio: true, condominios: true },
          configuracoes: { visualizar: true, editar: true },
          historico_absoluto: { limpar_dados: true }
        }
      };

      assert.equal(temAcessoGlobalExplicito(opMock), false, `${String(perfilInvalido)} não pode ter acesso global`);
      assert.equal(ehAdminCondominio(opMock), false, `${String(perfilInvalido)} não pode ser admin_condominio`);
      assert.equal(podeGerenciarOperadoresNoCondominio(opMock, CONDO_A), false, `${String(perfilInvalido)} não pode gerenciar operadores`);
      assert.equal(normalizarPerfilOperador(opMock), 'operador', `${String(perfilInvalido)} deve cair para operador`);

      // Frontend permissoesService
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'configuracoes', 'visualizar'), false);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'cadastros', 'operadores'), false);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'cadastros', 'editar_operadores'), false);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'cadastros', 'configurar_condominio'), false);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'cadastros', 'condominios'), false);
      assert.equal(permissoesSvc.verificarPermissao(opMock, 'historico_absoluto', 'limpar_dados'), false);

      // Backend authMiddleware
      const authRes = await testarNoBackend(opMock);
      assert.equal(authRes.ok, true);
      if (authRes.ok) {
        assert.equal(authRes.context.eAdminGlobal, false, `${String(perfilInvalido)} backend eAdminGlobal deve ser false`);
        assert.equal(authRes.context.perfilNormalizado, 'operador');
        assert.equal(podeGerenciarOperadoresServidor(authRes.context, CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'configuracoes', 'visualizar', CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'cadastros', 'operadores', CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'cadastros', 'configurar_condominio', CONDO_A), false);
        assert.equal(temPermissaoModuloBackend(authRes.context, 'historico_absoluto', 'limpar_dados', CONDO_A), false);
      }
    }

    // 2. admin_condominio administra SOMENTE seu condomínio principal (CONDO_A), jamais secundário (CONDO_B) ou global
    const adminCondoRow = {
      id: OP_GESTOR_A,
      auth_user_id: AUTH_GESTOR_A,
      nome: 'Admin Condomínio A',
      login: 'admin.condo.a',
      email: 'admin.a@condo.test',
      perfil: 'admin_condominio',
      nivel_acesso: 1,
      nivel_acesso_custom_id: 'nivel_1',
      condominio_id: CONDO_A,
      acesso_global_condominios: true, // mesmo se marcada indevidamente, admin_condominio não tem acesso global
      ativo: true,
      permissoes: {}
    };
    assert.equal(temAcessoGlobalExplicito(adminCondoRow), false);
    assert.equal(ehAdminCondominio(adminCondoRow), true);
    assert.equal(podeGerenciarOperadoresNoCondominio(adminCondoRow, CONDO_A), true);
    assert.equal(podeGerenciarOperadoresNoCondominio(adminCondoRow, CONDO_B), false);

    const authLocal = await testarNoBackend(adminCondoRow, [CONDO_B]);
    assert.equal(authLocal.ok, true);
    if (authLocal.ok) {
      assert.equal(authLocal.context.eAdminGlobal, false);
      assert.equal(authLocal.context.perfilNormalizado, 'admin_condominio');
      assert.equal(podeGerenciarOperadoresServidor(authLocal.context, CONDO_A), true);
      assert.equal(podeGerenciarOperadoresServidor(authLocal.context, CONDO_B), false);
      assert.equal(temPermissaoModuloBackend(authLocal.context, 'cadastros', 'operadores', CONDO_A), true);
      assert.equal(temPermissaoModuloBackend(authLocal.context, 'cadastros', 'operadores', CONDO_B), false);
      assert.equal(temPermissaoModuloBackend(authLocal.context, 'configuracoes', 'visualizar', CONDO_A), false);
    }

    // 3. admin_geral SEM flag global NÃO obtém acesso global nem privilégios administrativos
    const adminGeralSemFlag = {
      id: OP_GLOBAL,
      auth_user_id: AUTH_GLOBAL,
      nome: 'Admin Geral Sem Flag',
      login: 'global.sem.flag',
      email: 'global@porttohub.test',
      perfil: 'admin_geral',
      nivel_acesso: 0,
      nivel_acesso_custom_id: 'nivel_0',
      condominio_id: CONDO_A,
      acesso_global_condominios: false,
      ativo: true,
      permissoes: {}
    };
    assert.equal(temAcessoGlobalExplicito(adminGeralSemFlag), false);
    assert.equal(ehAdminCondominio(adminGeralSemFlag), false);
    assert.equal(podeGerenciarOperadoresNoCondominio(adminGeralSemFlag, CONDO_A), false);
    assert.equal(permissoesSvc.verificarPermissao(adminGeralSemFlag, 'configuracoes', 'visualizar'), false);
    assert.equal(permissoesSvc.verificarPermissao(adminGeralSemFlag, 'cadastros', 'operadores'), false);

    const authSemFlag = await testarNoBackend(adminGeralSemFlag);
    assert.equal(authSemFlag.ok, true);
    if (authSemFlag.ok) {
      assert.equal(authSemFlag.context.eAdminGlobal, false);
      assert.notEqual(authSemFlag.context.perfilNormalizado, 'admin_geral');
      assert.equal(podeGerenciarOperadoresServidor(authSemFlag.context, CONDO_A), false);
      assert.equal(temPermissaoModuloBackend(authSemFlag.context, 'configuracoes', 'visualizar', CONDO_A), false);
      assert.equal(temPermissaoModuloBackend(authSemFlag.context, 'cadastros', 'operadores', CONDO_A), false);
    }

    // 4. admin_geral INATIVO com flag global ligada NÃO obtém acesso global
    const adminGeralInativo = { ...adminGeralSemFlag, acesso_global_condominios: true, ativo: false };
    assert.equal(temAcessoGlobalExplicito(adminGeralInativo), false);
    assert.equal(permissoesSvc.verificarPermissao(adminGeralInativo, 'configuracoes', 'visualizar'), false);
    const authInativo = await testarNoBackend(adminGeralInativo);
    assert.equal(authInativo.ok, false);

    // 5. admin_geral ATIVO com flag global ligada MANTÉM acesso global completo
    const adminGeralAtivo = { ...adminGeralSemFlag, acesso_global_condominios: true, ativo: true };
    assert.equal(temAcessoGlobalExplicito(adminGeralAtivo), true);
    assert.equal(normalizarPerfilOperador(adminGeralAtivo), 'admin_geral');
    assert.equal(podeGerenciarOperadoresNoCondominio(adminGeralAtivo, CONDO_A), true);
    assert.equal(podeGerenciarOperadoresNoCondominio(adminGeralAtivo, CONDO_B), true);
    assert.equal(permissoesSvc.verificarPermissao(adminGeralAtivo, 'configuracoes', 'visualizar'), true);
    assert.equal(permissoesSvc.verificarPermissao(adminGeralAtivo, 'cadastros', 'condominios'), true);

    const authGlobal = await testarNoBackend(adminGeralAtivo);
    assert.equal(authGlobal.ok, true);
    if (authGlobal.ok) {
      assert.equal(authGlobal.context.eAdminGlobal, true);
      assert.equal(authGlobal.context.perfilNormalizado, 'admin_geral');
      assert.equal(podeGerenciarOperadoresServidor(authGlobal.context, CONDO_B), true);
      assert.equal(temPermissaoModuloBackend(authGlobal.context, 'configuracoes', 'visualizar', CONDO_A), true);
      assert.equal(temPermissaoModuloBackend(authGlobal.context, 'cadastros', 'condominios', CONDO_C), true);
    }

    // 6. Verificação estática SQL 05/11/12: ausência de admin_local / 'admin' / 'master' e Auditoria 12 detectando classificações indevidas
    const sql05 = fs.readFileSync(path.resolve('supabase/sql/05_FUNCOES_AUTORIZACAO.sql'), 'utf8');
    const sql11 = fs.readFileSync(path.resolve('supabase/sql/11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql'), 'utf8');
    const sql12 = fs.readFileSync(path.resolve('supabase/sql/12_AUDITORIA_FINAL_SEGURANCA.sql'), 'utf8');

    for (const [nome, sql] of [['05', sql05], ['11', sql11]] as const) {
      assert.equal(sql.includes('admin_local'), false, `${nome}: não deve conter admin_local`);
      assert.equal(sql.includes("'master'"), false, `${nome}: não deve conter perfil master`);
      assert.equal(sql.includes("'admin'"), false, `${nome}: não deve conter perfil admin`);

      const trechoGerenciar = sql.split('CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores(p_condominio_id TEXT)')[1]
        .split('CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores(p_condominio_id UUID)')[0];
      assert.ok(trechoGerenciar.includes("lower(trim(COALESCE(o.perfil, ''))) = 'admin_condominio'"), `${nome}: operador_pode_gerenciar_operadores deve exigir perfil = 'admin_condominio'`);

      const trechoPermMod = sql.split('CREATE OR REPLACE FUNCTION public.operador_tem_permissao_modulo(')[1]
        .split('CREATE OR REPLACE FUNCTION public.operador_tem_permissao_modulo(')[0];
      assert.ok(trechoPermMod.includes("v_perfil = 'admin_condominio'"), `${nome}: operador_tem_permissao_modulo deve exigir v_perfil = 'admin_condominio'`);
    }

    assert.ok(sql12.includes("pg_get_functiondef(p.oid) ILIKE '%v_perfil = ''admin_condominio''%'"));
    assert.ok(sql12.includes("pg_get_functiondef(p.oid) NOT ILIKE '%admin_local%'"));
    assert.ok(sql12.includes("pg_get_functiondef(p.oid) NOT ILIKE '%''master''%'"));
    assert.ok(sql12.includes("pg_get_functiondef(p.oid) NOT ILIKE '%''admin''%'"));
    assert.ok(sql12.includes("IN ('admin_local', 'admin', 'master')"));
    assert.ok(sql12.includes("coalesce\\([^,]*acesso_global_condominios,\\s*false\\)\\s*=\\s*true"));
    assert.ok(sql12.includes("coalesce\\([^,]*ativo,\\s*true\\)\\s*=\\s*true"));

    // 7. admin_condominio INATIVO não é reconhecido como admin local nem pode gerenciar operadores
    const adminCondoInativo = {
      ...adminCondoRow,
      acesso_global_condominios: false,
      ativo: false
    };
    assert.equal(ehAdminCondominio(adminCondoInativo), false, 'admin_condominio inativo não pode ser reconhecido por ehAdminCondominio()');
    assert.equal(podeGerenciarOperadoresNoCondominio(adminCondoInativo, CONDO_A), false, 'admin_condominio inativo não pode gerenciar operadores');
    assert.equal(temAcessoGlobalExplicito(adminCondoInativo), false);
    assert.equal(permissoesSvc.verificarPermissao(adminCondoInativo, 'cadastros', 'operadores'), false);
    assert.equal(permissoesSvc.verificarPermissao(adminCondoInativo, 'cadastros', 'editar_operadores'), false);

    const authLocalInativo = await testarNoBackend(adminCondoInativo);
    assert.equal(authLocalInativo.ok, false, 'Backend deve bloquear admin_condominio inativo');

    const ctxLocalInativoFake: any = {
      eAdminGlobal: false,
      perfilNormalizado: 'admin_condominio',
      operador: adminCondoInativo,
      allowedCondominioIds: new Set([CONDO_A])
    };
    assert.equal(podeGerenciarOperadoresServidor(ctxLocalInativoFake, CONDO_A), false);
    assert.equal(temPermissaoModuloBackend(ctxLocalInativoFake, 'cadastros', 'operadores', CONDO_A), false);

    permissoesSvc.limparCacheNiveisAcesso();
  } finally {
    (globalThis as any).localStorage = origStorage;
  }
});



