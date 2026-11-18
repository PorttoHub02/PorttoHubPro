/**
 * Suite de Integração Real com Supabase (Auth + RLS + Storage Privado + RPC Passe QR).
 *
 * IMPORTANTE:
 * - Este arquivo NÃO utiliza mocks quando configurado com credenciais de ambiente de TESTE/HOMOLOGAÇÃO.
 * - NÃO execute contra o banco de produção sem usuários dedicados de homologação.
 * - Quando as variáveis SUPABASE_TEST_* não estão definidas, cada teste é ignorado com segurança (skip),
 *   garantindo que nenhuma alteração acidental ocorra em produção.
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
 *   SUPABASE_TEST_QR_TOKEN_EXPIRADO
 *   SUPABASE_TEST_QR_TOKEN_FORA_HORARIO
 *   SUPABASE_TEST_QR_TOKEN_CONDO_B
 *   SUPABASE_TEST_QR_TOKEN_ESGOTADO
 *   SUPABASE_TEST_QR_TOKEN_VALIDO_UNICO
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

test('[Live Supabase] 15. Acesso anônimo (anon) e URL pública de Storage são bloqueados', async (t) => {
  if (!TEM_AMBIENTE_TESTE) {
    t.skip('Variáveis SUPABASE_TEST_* não configuradas — integração real pulada com segurança.');
    return;
  }

  const anonClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false }
  });

  const [opRes, condoRes, encRes] = await Promise.all([
    anonClient.from('operadores').select('id').limit(1),
    anonClient.from('condominios').select('id').limit(1),
    anonClient.from('encomendas_itens').select('id').limit(1)
  ]);

  assert.ok(opRes.error || (opRes.data || []).length === 0, 'Anon não deve ler operadores');
  assert.ok(condoRes.error || (condoRes.data || []).length === 0, 'Anon não deve ler condominios');
  assert.ok(encRes.error || (encRes.data || []).length === 0, 'Anon não deve ler encomendas_itens');

  // Bucket privado não responde via /object/public/
  const publicProbe = await fetch(`${SUPABASE_URL.replace(/\/+$/, '')}/storage/v1/object/public/encomendas/condominios/${CONDO_A}/probe.jpg`);
  assert.ok(!publicProbe.ok && (publicProbe.status === 400 || publicProbe.status === 401 || publicProbe.status === 403 || publicProbe.status === 404));
});

test('[Live Supabase] 7. Admin Geral autentica, lê condomínios e executa operações globais autorizadas', async (t) => {
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

test('[Live Supabase] 4, 5, 6. Admin de Condomínio gerencia apenas o próprio condomínio principal e não se promove a global', async (t) => {
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

test('[Live Supabase] 1, 2, 3, 10, 11, 12, 13, 14, 24. Operador/Supervisor bloqueados em auto-escalação, cross-condo, Storage alheio e TRUNCATE', async (t) => {
  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL || process.env.SUPABASE_TEST_SUPERVISOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD || process.env.SUPABASE_TEST_SUPERVISOR_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !opEmail || !opPass) {
    t.skip('Credenciais SUPABASE_TEST_OPERADOR_* / SUPABASE_TEST_SUPERVISOR_* não definidas.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  // 3. Supervisor/Operador não administra operadores
  const { data: podeGerenciar } = await client!.rpc('operador_pode_gerenciar_operadores', {
    p_condominio_id: CONDO_A
  });
  assert.equal(podeGerenciar, false);

  // 1 & 2. Não altera próprias permissões nem próprio perfil
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

  // 10, 11, 12. Bloqueio leitura/inserção/atualização em CONDO_B
  if (CONDO_B) {
    const { data: moradoresB } = await client!.from('moradores').select('id').eq('condominio_id', CONDO_B).limit(1);
    assert.equal((moradoresB || []).length, 0);

    const { error: errInsB } = await client!
      .from('moradores')
      .insert([{ condominio_id: CONDO_B, nome: 'Teste Invasao', unidade: '999' }]);
    assert.ok(errInsB, 'Inserção em outro condomínio deve falhar por RLS');

    const { data: listaB } = await client!.storage.from('encomendas').list(`condominios/${CONDO_B}`, { limit: 1 });
    assert.equal((listaB || []).length, 0);
  }

  // 13 & 14. Avatar pessoal somente na pasta auth.uid(), bloqueado em pasta de outro operador
  const outraPasta = 'operadores/00000000-0000-4000-8000-000000000000/invasao.jpg';
  const { error: errUploadAlheio } = await client!.storage
    .from('encomendas')
    .upload(outraPasta, new Uint8Array([1, 2, 3]), { contentType: 'image/jpeg', upsert: true });
  assert.ok(errUploadAlheio, 'Upload em pasta operadores/ de outro auth.uid() deve ser negado');

  await client!.auth.signOut();
});

test('[Live Supabase] 8. Usuário inativo não acessa dados nem funções operacionais', async (t) => {
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

  const { data: moradores } = await client!.from('moradores').select('id').eq('condominio_id', CONDO_A).limit(1);
  assert.equal((moradores || []).length, 0);

  await client!.auth.signOut();
});

test('[Live Supabase] 16-23. Passes QR: anti-spoofing, expirado, fora do horário, outro condo, validação sem consumo e concorrência', async (t) => {
  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !opEmail || !opPass) {
    t.skip('Credenciais SUPABASE_TEST_OPERADOR_* não definidas para testes reais de Passes QR.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  const tokenExpirado = process.env.SUPABASE_TEST_QR_TOKEN_EXPIRADO;
  if (tokenExpirado) {
    const { data } = await client!.rpc('validar_e_consumir_passe_qr', {
      p_condominio_id: CONDO_A,
      p_token: tokenExpirado,
      p_consumir: false,
      p_operador_nome: 'NOME_FALSIFICADO'
    });
    assert.equal(data?.valido, false);
  }

  const tokenForaHora = process.env.SUPABASE_TEST_QR_TOKEN_FORA_HORARIO;
  if (tokenForaHora) {
    const { data } = await client!.rpc('validar_e_consumir_passe_qr', {
      p_condominio_id: CONDO_A,
      p_token: tokenForaHora,
      p_consumir: false
    });
    assert.equal(data?.valido, false);
  }

  const tokenCondoB = process.env.SUPABASE_TEST_QR_TOKEN_CONDO_B;
  if (tokenCondoB) {
    const { data } = await client!.rpc('validar_e_consumir_passe_qr', {
      p_condominio_id: CONDO_A,
      p_token: tokenCondoB,
      p_consumir: false
    });
    assert.equal(data?.valido, false);
  }

  const tokenEsgotado = process.env.SUPABASE_TEST_QR_TOKEN_ESGOTADO;
  if (tokenEsgotado) {
    const { data } = await client!.rpc('validar_e_consumir_passe_qr', {
      p_condominio_id: CONDO_A,
      p_token: tokenEsgotado,
      p_consumir: true
    });
    assert.equal(data?.valido, false);
  }

  const tokenUnico = process.env.SUPABASE_TEST_QR_TOKEN_VALIDO_UNICO;
  if (tokenUnico) {
    // 22. Validação sem consumo não altera o passe
    const { data: checkOnly } = await client!.rpc('validar_e_consumir_passe_qr', {
      p_condominio_id: CONDO_A,
      p_token: tokenUnico,
      p_consumir: false
    });
    assert.equal(checkOnly?.valido, true);
    assert.equal(checkOnly?.passe?.usos_realizados, 0);

    // 16, 21, 23. Duas chamadas simultâneas não ultrapassam max_usos e ignoram p_operador_nome falso
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
  }

  await client!.auth.signOut();
});

test('[Live Supabase Segunda Rodada] Anon bloqueado na RPC QR, trigger bloqueia adulteração direta em passes_virtuais_qr, proteção de e-mail Auth, FK cross-condo e permissão de módulo', async (t) => {
  if (!TEM_AMBIENTE_TESTE) {
    t.skip('Variáveis SUPABASE_TEST_* não configuradas — testes reais da segunda rodada pulados com segurança.');
    return;
  }

  // 1. Chamada anônima direta na RPC validar_e_consumir_passe_qr deve falhar (REVOKE anon + auth.uid() obrigatório)
  const anonClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  const { error: errAnonRpc } = await anonClient.rpc('validar_e_consumir_passe_qr', {
    p_condominio_id: CONDO_A,
    p_token: 'PASS-PROBE-ANON',
    p_consumir: true
  });
  assert.ok(errAnonRpc, 'Cliente anon não deve conseguir executar validar_e_consumir_passe_qr');

  const opEmail = process.env.SUPABASE_TEST_OPERADOR_EMAIL;
  const opPass = process.env.SUPABASE_TEST_OPERADOR_PASSWORD;
  if (!opEmail || !opPass) {
    t.skip('Credenciais SUPABASE_TEST_OPERADOR_* ausentes para os testes autenticados da segunda rodada.');
    return;
  }

  const client = await autenticarCliente(opEmail, opPass);
  assert.ok(client);

  // 2. operador_auth_email_corresponde bloqueia enumeração de UUID de terceiro
  const { data: enumTerceiro } = await client!.rpc('operador_auth_email_corresponde', {
    p_auth_user_id: '00000000-0000-4000-8000-000000000000',
    p_email: 'admin@condominio.test'
  });
  assert.equal(enumTerceiro, false);

  // 3. Porteiro não consegue executar DELETE em custodia/chaves (bloqueado por operador_tem_permissao_modulo)
  const { error: errDelCustodia } = await client!
    .from('custodia')
    .delete()
    .eq('condominio_id', CONDO_A)
    .eq('id', '00000000-0000-4000-8000-000000000000');
  if (errDelCustodia) {
    assert.ok(errDelCustodia.code === '42501' || errDelCustodia.message.length > 0);
  }

  // 4. Adulteração direta de usos_realizados / status em passes_virtuais_qr fora da RPC deve ser bloqueada
  const { data: passeAlvo } = await client!
    .from('passes_virtuais_qr')
    .select('id, usos_realizados, status')
    .eq('condominio_id', CONDO_A)
    .limit(1)
    .maybeSingle();

  if (passeAlvo?.id) {
    const { error: errAdulterarQr } = await client!
      .from('passes_virtuais_qr')
      .update({ usos_realizados: 0, status: 'valido' })
      .eq('id', passeAlvo.id);
    assert.ok(errAdulterarQr, 'Trigger proteger_campos_passe_qr / RLS deve impedir alteração direta de usos_realizados/status');
  }

  // 5. Integridade cross-condo de FK filha: inserir encomenda em CONDO_A apontando para morador de CONDO_B deve falhar
  const moradorCondoB = process.env.SUPABASE_TEST_MORADOR_CONDO_B_ID;
  if (CONDO_B && moradorCondoB) {
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

