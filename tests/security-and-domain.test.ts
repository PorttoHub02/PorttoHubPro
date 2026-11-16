import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import {
  resolverContextoCondominiosOperador,
  temAcessoGlobalExplicito,
  isCondominioIdValido,
  verificarCredenciaisOperadorSupabaseAuth
} from '../src/services/autorizacaoService.ts';
import {
  buscarMoradoresDaUnidadeExata,
  validarDestinatarioAntesGravacao,
  enriquecerEncomendaComMorador
} from '../src/services/encomendasService.ts';
import {
  extrairCaminhoStorageSupabase,
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
      perfil: 'admin',
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
    }
  ];

  const authUpdates: string[] = [];

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

    if (url.pathname === '/rest/v1/operadores') {
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

    if (url.pathname === '/rest/v1/operador_condominios') {
      return new Response(JSON.stringify([]), { status: 200 });
    }

    if (url.pathname.startsWith('/auth/v1/admin/users/')) {
      const targetAuthId = decodeURIComponent(url.pathname.split('/').pop() || '');
      authUpdates.push(targetAuthId);
      return new Response(JSON.stringify({ id: targetAuthId }), { status: 200 });
    }

    if (url.pathname === '/auth/v1/admin/users' && method === 'POST') {
      return new Response(JSON.stringify({ msg: 'User already registered' }), { status: 422 });
    }

    if (url.pathname === '/auth/v1/admin/users' && method === 'GET') {
      const filterEmail = (url.searchParams.get('filter') || '').toLowerCase();
      const matched = operadoresDb
        .filter(o => o.email.toLowerCase() === filterEmail)
        .map(o => ({ id: o.auth_user_id, email: o.email }));
      return new Response(JSON.stringify({ users: matched }), { status: 200 });
    }

    return new Response(JSON.stringify({ error: `Unmocked ${method} ${url.pathname}` }), { status: 404 });
  };

  return {
    authUpdates,
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

test('Regra C: Login "admin", perfil "master" ou nivel_acesso <= 1 SEM flag explícito NÃO ganham acesso global', () => {
  const adminSemFlag = {
    id: 'fake-global',
    login: 'admin',
    perfil: 'master',
    nivel_acesso: 1,
    condominio_id: 'todos',
    acesso_global_condominios: false
  };
  assert.equal(temAcessoGlobalExplicito(adminSemFlag), false);

  const resSemVinculo = resolverContextoCondominiosOperador({
    operador: adminSemFlag,
    condominiosDisponiveis: CONDOS,
    vinculosExplicitosIds: [],
    tabelaVinculosDisponivel: true
  });
  assert.equal(resSemVinculo.eAdminGeral, false);
  assert.equal(resSemVinculo.bloqueado, true);

  const adminComFlag = { ...adminSemFlag, acesso_global_condominios: true };
  assert.equal(temAcessoGlobalExplicito(adminComFlag), true);
  const resComFlag = resolverContextoCondominiosOperador({
    operador: adminComFlag,
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
