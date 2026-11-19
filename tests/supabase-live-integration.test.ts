/**
 * Suite de Integração Real com Supabase (Auth + RLS + Storage Privado + RPC Passe QR + Autoria + Níveis Customizados).
 *
 * IMPORTANTE:
 * - Este arquivo NÃO utiliza mocks quando configurado com credenciais de ambiente de TESTE/HOMOLOGAÇÃO.
 * - NÃO execute contra o banco de produção sem usuários dedicados de homologação.
 * - Quando variáveis SUPABASE_TEST_* obrigatórias ou fixtures específicas não estão definidas,
 *   o teste respectivo chama explicitamente `t.skip(...)` — nunca retorna PASS silencioso.
 *
 * Variáveis esperadas para execução real (homologação/teste):
 *   SUPABASE_TEST_URL
 *   SUPABASE_TEST_ANON_KEY
 *   SUPABASE_TEST_CONDO_A_ID
 *   SUPABASE_TEST_CONDO_B_ID
 *   SUPABASE_TEST_ADMIN_GERAL_EMAIL / SUPABASE_TEST_ADMIN_GERAL_PASSWORD
 *   SUPABASE_TEST_ADMIN_CONDO_EMAIL / SUPABASE_TEST_ADMIN_CONDO_PASSWORD
 *   SUPABASE_TEST_SUPERVISOR_EMAIL / SUPABASE_TEST_SUPERVISOR_PASSWORD
 *   SUPABASE_TEST_OPERADOR_EMAIL / SUPABASE_TEST_OPERADOR_PASSWORD
 *   SUPABASE_TEST_INATIVO_EMAIL / SUPABASE_TEST_INATIVO_PASSWORD
 *   SUPABASE_TEST_CUSTOM_OPERADOR_EMAIL / SUPABASE_TEST_CUSTOM_OPERADOR_PASSWORD
 *   SUPABASE_TEST_CUSTOM_NIVEL_MODULO_PERMITIDO (opcional, default: 'ocorrencias')
 *   SUPABASE_TEST_CUSTOM_NIVEL_MODULO_NEGADO (opcional, default: 'custodia')
 *   SUPABASE_TEST_QR_TOKEN_EXPIRADO
 *   SUPABASE_TEST_QR_TOKEN_FORA_HORARIO
 *   SUPABASE_TEST_QR_TOKEN_CONDO_B
 *   SUPABASE_TEST_QR_TOKEN_ESGOTADO
 *   SUPABASE_TEST_QR_TOKEN_VALIDO_UNICO
 *   SUPABASE_TEST_MORADOR_CONDO_B_ID
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.SUPABASE_TEST_URL || '';
const SUPABASE_ANON_KEY = process.env.SUPABASE_TEST_ANON_KEY || '';
const CONDO_A = process.env.SUPABASE_TEST_CONDO_A_ID || '';
const CONDO_B = process.env.SUPABASE_TEST_CONDO_B_ID || '';

const TEM_AMBIENTE_TESTE = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY && CONDO_A);

async function autenticarCliente(email?: string, password?: string): Promise<SupabaseClient | null> {
  if (!TEM_AMBIENTE_TESTE || !email || !password) return null;
  const client = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  const { error } = await client.auth.signInWithPassword({ email, password });
  if (error) {
    throw new Error(`Falha no login de teste (${email}): ${error.message}`);
  }
  return client;
}

test('[Live Supabase] Anon bloqueado em tabelas, Storage público e RPC validar_e_consumir_passe_qr', async (t) => {
  if (!TEM_AMBIENTE_TESTE) {
    t.skip('Variáveis SUPABASE_TEST_* não configuradas — integração real pulada com segurança.');
    return;
  }

  const anonClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false }
  });

  const [opRes, condoRes, encRes, histRes] = await Promise.all([
    anonClient.from('operadores').select('id').limit(1),
    anonClient.from('condominios').select('id').limit(1),
    anonClient.from('encomendas_itens').select('id').limit(1),
    anonClient.from('historico_absoluto').select('id').limit(1)
  ]);

  assert.ok(opRes.error || (opRes.data || []).length === 0, 'Anon não deve ler operadores');
  assert.ok(condoRes.error || (condoRes.data || []).length === 0, 'Anon não deve ler condominios');
  assert.ok(encRes.error || (encRes.data || []).length === 0, 'Anon não deve ler encomendas_itens');
  assert.ok(histRes.error || (histRes.data || []).length === 0, 'Anon não deve ler historico_absoluto');

  const { error: errAnonRpc } = await anonClient.rpc('validar_e_consumir_passe_qr', {
    p_condominio_id: CONDO_A,
    p_token: 'PASS-PROBE-ANON',
    p_consumir: true
  });
  assert.ok(errAnonRpc, 'Cliente anon não deve conseguir executar validar_e_consumir_passe_qr');

  const publicProbe = await fetch(`${SUPABASE_URL.replace(/\/+$/, '')}/storage/v1/object/public/encomendas/condominios/${CONDO_A}/probe.jpg`);
  assert.ok(!publicProbe.ok && (publicProbe.status === 400 || publicProbe.status === 401 || publicProbe.status === 403 || publicProbe.status === 404));
});

test('[Live Supabase] Admin Geral autentica, lê condomínios e confirma acesso global', async (t) => {
  const email = process.env.SUPABASE_TEST_ADMIN_GERAL_EMAIL;
  const password = process.env.SUPABASE_TEST_ADMIN_GERAL_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !email || !password) {
    t.skip('Credenciais SUPABASE_TEST_ADMIN_GERAL_* não definidas.');
    return;
  }

  const client = await autenticarCliente(email, password);
  assert.ok(client);

  const { data: globalFlag, error: errRpc } = await client!.rpc('operador_tem_acesso_global');
  assert.equal(errRpc, null);
  assert.equal(globalFlag, true);

  const { data: condos, error: errCondos } = await client!.from('condominios').select('id, nome');
  assert.equal(errCondos, null);
  assert.ok(Array.isArray(condos) && condos.length >= 1);

  await client!.auth.signOut();
});

test('[Live Supabase] Admin de Condomínio gerencia apenas condomínio principal e não se auto-promove a global', async (t) => {
  const email = process.env.SUPABASE_TEST_ADMIN_CONDO_EMAIL;
  const password = process.env.SUPABASE_TEST_ADMIN_CONDO_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !email || !password || !CONDO_B) {
    t.skip('Credenciais SUPABASE_TEST_ADMIN_CONDO_* ou CONDO_B não definidas.');
    return;
  }

  const client = await autenticarCliente(email, password);
  assert.ok(client);

  const { data: podePrincipal } = await client!.rpc('operador_pode_gerenciar_operadores', {
    p_condominio_id: CONDO_A
  });
  assert.equal(podePrincipal, true);

  const { data: podeSecundario } = await client!.rpc('operador_pode_gerenciar_operadores', {
    p_condominio_id: CONDO_B
  });
  assert.equal(podeSecundario, false);

  const { data: opId } = await client!.rpc('operador_atual_id');
  assert.ok(opId);

  const { error: errEscalacao } = await client!
    .from('operadores')
    .update({ acesso_global_condominios: true, perfil: 'admin_geral' })
    .eq('id', opId);
  assert.ok(errEscalacao, 'RLS/Trigger deve bloquear auto-escalação para admin_geral');

  await client!.auth.signOut();
});

test('[Live Supabase] Operador bloqueado em auto-escalação, enumeração auth_email, DELETE custodia e Storage de outro operador', async (t) => {
  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL || process.env.SUPABASE_TEST_SUPERVISOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD || process.env.SUPABASE_TEST_SUPERVISOR_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !opEmail || !opPass) {
    t.skip('Credenciais SUPABASE_TEST_OPERADOR_* / SUPABASE_TEST_SUPERVISOR_* não definidas.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  const { data: podeGerenciar } = await client!.rpc('operador_pode_gerenciar_operadores', {
    p_condominio_id: CONDO_A
  });
  assert.equal(podeGerenciar, false);

  const { data: opId } = await client!.rpc('operador_atual_id');
  assert.ok(opId);

  const { error: errPerm } = await client!
    .from('operadores')
    .update({ permissoes: { configuracoes: { visualizar: true, editar: true } } })
    .eq('id', opId);
  assert.ok(errPerm, 'Operador não pode alterar a própria coluna permissoes');

  const { error: errPerfil } = await client!
    .from('operadores')
    .update({ perfil: 'admin_condominio' })
    .eq('id', opId);
  assert.ok(errPerfil, 'Operador não pode alterar o próprio perfil');

  const { data: enumTerceiro } = await client!.rpc('operador_auth_email_corresponde', {
    p_auth_user_id: '00000000-0000-4000-8000-000000000000',
    p_email: 'admin@condominio.test'
  });
  assert.equal(enumTerceiro, false);

  // Porteiro/Operador não possui permissão DELETE em custodia; erro RLS é obrigatório
  const { error: errDelCustodia } = await client!
    .from('custodia')
    .delete()
    .eq('condominio_id', CONDO_A)
    .eq('id', '00000000-0000-4000-8000-000000000000');
  assert.ok(errDelCustodia, 'RLS deve negar DELETE em custodia para operador sem permissão');

  const outraPasta = 'operadores/00000000-0000-4000-8000-000000000000/invasao.jpg';
  const { error: errUploadAlheio } = await client!.storage
    .from('encomendas')
    .upload(outraPasta, new Uint8Array([1, 2, 3]), { contentType: 'image/jpeg', upsert: true });
  assert.ok(errUploadAlheio, 'Upload em pasta operadores/ de outro auth.uid() deve ser negado');

  await client!.auth.signOut();
});

test('[Live Supabase] Isolamento cross-condomínio real (CONDO_A vs CONDO_B: leitura, escrita, Storage e FK filha)', async (t) => {
  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !CONDO_B || !opEmail || !opPass) {
    t.skip('CONDO_B ou credenciais SUPABASE_TEST_OPERADOR_* não configurados para teste de isolamento entre 2 condomínios.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  const { data: podeCondoB } = await client!.rpc('operador_pode_acessar_condominio', {
    p_condominio_id: CONDO_B
  });
  assert.equal(podeCondoB, false, 'Operador do Condomínio A não deve acessar Condomínio B');

  const { data: moradoresB, error: errMorB } = await client!.from('moradores').select('id').eq('condominio_id', CONDO_B).limit(1);
  assert.ok(errMorB || (moradoresB || []).length === 0, 'Leitura cross-condo deve retornar vazio ou erro');

  const { error: errInsB } = await client!
    .from('moradores')
    .insert([{ condominio_id: CONDO_B, nome: 'Teste Invasao', unidade: '999' }]);
  assert.ok(errInsB, 'Inserção em outro condomínio deve falhar por RLS');

  const { data: listaB, error: errStorageB } = await client!.storage.from('encomendas').list(`condominios/${CONDO_B}`, { limit: 1 });
  assert.ok(errStorageB || (listaB || []).length === 0, 'Listagem de Storage do Condomínio B deve ser bloqueada');

  const moradorCondoB = process.env.SUPABASE_TEST_MORADOR_CONDO_B_ID;
  if (moradorCondoB) {
    const { error: errFkCross } = await client!
      .from('encomendas_itens')
      .insert([{
        condominio_id: CONDO_A,
        morador_id: moradorCondoB,
        bloco: 'A',
        unidade: '101',
        status: 'recebida'
      }]);
    assert.ok(errFkCross, 'RLS deve impedir vínculo com morador_id de outro condomínio');
  }

  await client!.auth.signOut();
});

test('[Live Supabase] Proteção de autoria: bloqueia falsificação de operador_id / operador_nome em historico_absoluto e registros_acesso', async (t) => {
  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !opEmail || !opPass) {
    t.skip('Credenciais SUPABASE_TEST_OPERADOR_* não configuradas para teste de autoria.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  const { data: opIdReal } = await client!.rpc('operador_atual_id');
  assert.ok(opIdReal, 'Operador autenticado deve ter operador_atual_id() válido');
  const fakeOperadorId = '99999999-9999-4999-8999-999999999999';

  // 1. Tentativa de falsificar autoria em historico_absoluto
  const histRes = await client!
    .from('historico_absoluto')
    .insert([{
      condominio_id: CONDO_A,
      operador_id: fakeOperadorId,
      operador_nome: 'IMPOSTOR_AUDITORIA',
      operador_login: 'impostor',
      modulo: 'teste_seguranca',
      acao: 'probe_autoria',
      descricao: 'Teste automatizado de autoria'
    }])
    .select('id, operador_id, operador_nome, operador_login')
    .maybeSingle();

  assert.ok(
    histRes.error || (
      histRes.data &&
      histRes.data.operador_id === opIdReal &&
      histRes.data.operador_nome !== 'IMPOSTOR_AUDITORIA'
    ),
    'RLS/Trigger deve bloquear operador_id forjado ou sobrescrever autoria com o operador real do JWT'
  );

  // 2. Tentativa de falsificar autoria em registros_acesso
  const regRes = await client!
    .from('registros_acesso')
    .insert([{
      condominio_id: CONDO_A,
      nome: 'Visitante Probe Autoria',
      tipo_pessoa: 'visitante',
      tipo_acesso: 'entrada',
      operador_registro: 'IMPOSTOR_PORTARIA'
    }])
    .select('id, operador_registro')
    .maybeSingle();

  assert.ok(
    regRes.error || (
      regRes.data &&
      regRes.data.operador_registro !== 'IMPOSTOR_PORTARIA'
    ),
    'Trigger proteger_autoria_registros_acesso deve impedir spoof de operador_registro'
  );

  await client!.auth.signOut();
});

test('[Live Supabase] Nível personalizado em configuracoes.niveis_acesso avaliado no PostgreSQL (operador_tem_permissao_modulo)', async (t) => {
  const customEmail = process.env.SUPABASE_TEST_CUSTOM_OPERADOR_EMAIL;
  const customPass = process.env.SUPABASE_TEST_CUSTOM_OPERADOR_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !customEmail || !customPass) {
    t.skip('Credenciais SUPABASE_TEST_CUSTOM_OPERADOR_* não configuradas para validar nível customizado em runtime.');
    return;
  }

  const modPermitido = process.env.SUPABASE_TEST_CUSTOM_NIVEL_MODULO_PERMITIDO || 'ocorrencias';
  const modNegado = process.env.SUPABASE_TEST_CUSTOM_NIVEL_MODULO_NEGADO || 'custodia';

  const client = await autenticarCliente(customEmail, customPass);
  assert.ok(client);

  const { data: podePermitido, error: errPermOk } = await client!.rpc('operador_tem_permissao_modulo', {
    p_condominio_id: CONDO_A,
    p_modulo: modPermitido,
    p_acao: 'visualizar'
  });
  assert.equal(errPermOk, null);
  assert.equal(podePermitido, true, `Nível customizado deve autorizar ${modPermitido}.visualizar`);

  const { data: podeNegado, error: errPermDeny } = await client!.rpc('operador_tem_permissao_modulo', {
    p_condominio_id: CONDO_A,
    p_modulo: modNegado,
    p_acao: 'excluir'
  });
  assert.equal(errPermDeny, null);
  assert.equal(podeNegado, false, `Nível customizado deve negar ${modNegado}.excluir`);

  await client!.auth.signOut();
});

test('[Live Supabase] Usuário inativo não acessa dados nem funções operacionais', async (t) => {
  const email = process.env.SUPABASE_TEST_INATIVO_EMAIL;
  const password = process.env.SUPABASE_TEST_INATIVO_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !email || !password) {
    t.skip('Credenciais SUPABASE_TEST_INATIVO_* não definidas.');
    return;
  }

  const client = await autenticarCliente(email, password);
  assert.ok(client);

  const { data: podeCondo } = await client!.rpc('operador_pode_acessar_condominio', {
    p_condominio_id: CONDO_A
  });
  assert.equal(podeCondo, false);

  const { data: moradores, error: errMor } = await client!.from('moradores').select('id').eq('condominio_id', CONDO_A).limit(1);
  assert.ok(errMor || (moradores || []).length === 0);

  await client!.auth.signOut();
});

test('[Live Supabase] Passe QR: trigger bloqueia alteração direta de usos_realizados e status fora da RPC', async (t) => {
  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !opEmail || !opPass) {
    t.skip('Credenciais SUPABASE_TEST_OPERADOR_* não definidas para teste de adulteração direta QR.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  const { data: passeAlvo } = await client!
    .from('passes_virtuais_qr')
    .select('id, usos_realizados, status')
    .eq('condominio_id', CONDO_A)
    .limit(1)
    .maybeSingle();

  if (!passeAlvo?.id) {
    await client!.auth.signOut();
    t.skip('Nenhum passe_virtual_qr de fixture encontrado no condomínio de teste.');
    return;
  }

  const { error: errAdulterarQr } = await client!
    .from('passes_virtuais_qr')
    .update({ usos_realizados: 0, status: 'valido' })
    .eq('id', passeAlvo.id);
  assert.ok(errAdulterarQr, 'Trigger proteger_campos_passe_qr / RLS deve impedir alteração direta de usos_realizados/status');

  await client!.auth.signOut();
});

test('[Live Supabase] Passes QR: expirado, fora do horário, outro condomínio e esgotado são rejeitados', async (t) => {
  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD;
  const tokenExpirado = process.env.SUPABASE_TEST_QR_TOKEN_EXPIRADO;
  const tokenForaHora = process.env.SUPABASE_TEST_QR_TOKEN_FORA_HORARIO;
  const tokenCondoB = process.env.SUPABASE_TEST_QR_TOKEN_CONDO_B;
  const tokenEsgotado = process.env.SUPABASE_TEST_QR_TOKEN_ESGOTADO;

  if (!TEM_AMBIENTE_TESTE || !opEmail || !opPass || !tokenExpirado || !tokenForaHora || !tokenCondoB || !tokenEsgotado) {
    t.skip('Credenciais ou tokens fixtures (EXPIRADO/FORA_HORARIO/CONDO_B/ESGOTADO) não configurados.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  const casos = [
    { token: tokenExpirado, consumir: false, nome: 'expirado' },
    { token: tokenForaHora, consumir: false, nome: 'fora do horário' },
    { token: tokenCondoB, consumir: false, nome: 'outro condomínio' },
    { token: tokenEsgotado, consumir: true, nome: 'esgotado' }
  ];

  for (const caso of casos) {
    const resQr: { data: any; error: any } = await client!.rpc('validar_e_consumir_passe_qr', {
      p_condominio_id: CONDO_A,
      p_token: caso.token,
      p_consumir: caso.consumir,
      p_operador_nome: 'NOME_FALSIFICADO'
    });
    assert.equal(resQr.error, null);
    assert.equal(resQr.data?.valido, false, `Passe ${caso.nome} deve ser rejeitado`);
  }

  await client!.auth.signOut();
});

test('[Live Supabase] Passes QR: validação sem consumo + concorrência (2 chamadas simultâneas max_usos=1) + anti-spoofing', async (t) => {
  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD;
  const tokenUnico = process.env.SUPABASE_TEST_QR_TOKEN_VALIDO_UNICO;
  if (!TEM_AMBIENTE_TESTE || !opEmail || !opPass || !tokenUnico) {
    t.skip('Credenciais SUPABASE_TEST_OPERADOR_* ou SUPABASE_TEST_QR_TOKEN_VALIDO_UNICO não configurados.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  const { data: checkOnly } = await client!.rpc('validar_e_consumir_passe_qr', {
    p_condominio_id: CONDO_A,
    p_token: tokenUnico,
    p_consumir: false
  });
  assert.equal(checkOnly?.valido, true);
  assert.equal(checkOnly?.passe?.usos_realizados, 0);

  const [r1, r2] = await Promise.all([
    client!.rpc('validar_e_consumir_passe_qr', {
      p_condominio_id: CONDO_A,
      p_token: tokenUnico,
      p_consumir: true,
      p_operador_nome: 'INVASOR_SPOOF_1'
    }),
    client!.rpc('validar_e_consumir_passe_qr', {
      p_condominio_id: CONDO_A,
      p_token: tokenUnico,
      p_consumir: true,
      p_operador_nome: 'INVASOR_SPOOF_2'
    })
  ]);

  const sucessos = [r1.data, r2.data].filter(d => d?.valido === true);
  assert.equal(sucessos.length, 1);
  assert.notEqual(sucessos[0]?.registro?.operador_entrada_nome, 'INVASOR_SPOOF_1');
  assert.notEqual(sucessos[0]?.registro?.operador_entrada_nome, 'INVASOR_SPOOF_2');

  await client!.auth.signOut();
});

test('[Live Supabase] Histórico Absoluto bloqueia módulo/ação administrativa sem permissão (Limpeza de Dados / custodia.excluir)', async (t) => {
  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !opEmail || !opPass) {
    t.skip('Credenciais SUPABASE_TEST_OPERADOR_* não configuradas para validar bloqueio de auditoria indevida.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  const { error: errLimpeza } = await client!
    .from('historico_absoluto')
    .insert([{
      condominio_id: CONDO_A,
      modulo: 'Limpeza de Dados',
      acao: 'LIMPEZA_PERIODO',
      descricao: 'Probe não autorizado de limpeza por operador'
    }]);
  assert.ok(errLimpeza, 'RLS/Trigger deve bloquear registro de Limpeza de Dados por operador comum');

  const { error: errCustodiaExcluir } = await client!
    .from('historico_absoluto')
    .insert([{
      condominio_id: CONDO_A,
      modulo: 'custodia',
      acao: 'excluir',
      descricao: 'Probe não autorizado de exclusão de custódia por operador'
    }]);
  assert.ok(errCustodiaExcluir, 'RLS/Trigger deve bloquear registro custodia/excluir por operador comum');

  await client!.auth.signOut();
});

test('[Live Supabase] Operador com nivel_acesso=1 (ou custom nivel_1) não recebe poderes administrativos no PostgreSQL', async (t) => {
  const email = process.env.SUPABASE_TEST_OP_NIVEL1_EMAIL;
  const password = process.env.SUPABASE_TEST_OP_NIVEL1_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !email || !password) {
    t.skip('Credenciais opcionais SUPABASE_TEST_OP_NIVEL1_* não configuradas.');
    return;
  }

  const client = await autenticarCliente(email, password);
  assert.ok(client);

  const [{ data: podeGerenciar }, { data: podeOp }, { data: podeLimpar }] = await Promise.all([
    client!.rpc('operador_pode_gerenciar_operadores', { p_condominio_id: CONDO_A }),
    client!.rpc('operador_tem_permissao_modulo', { p_condominio_id: CONDO_A, p_modulo: 'cadastros', p_acao: 'operadores' }),
    client!.rpc('operador_tem_permissao_modulo', { p_condominio_id: CONDO_A, p_modulo: 'historico_absoluto', p_acao: 'limpar_dados' })
  ]);

  assert.equal(podeGerenciar, false, 'Operador com nivel_acesso=1 não pode gerenciar operadores');
  assert.equal(podeOp, false, 'Operador com nivel_acesso=1 não pode acessar cadastros.operadores');
  assert.equal(podeLimpar, false, 'Operador com nivel_acesso=1 não pode limpar historico_absoluto');

  await client!.auth.signOut();
});

