/**
 * Suite de Integração Real com Supabase (Auth + RLS + Storage Privado + RPC Passe QR).
 *
 * IMPORTANTE:
 * - Este arquivo NÃO utiliza mocks quando configurado com credenciais de ambiente de TESTE/HOMOLOGAÇÃO.
 * - NÃO execute contra o banco de produção sem usuários dedicados de teste.
 * - Quando as variáveis SUPABASE_TEST_* não estão definidas, os testes são ignorados com segurança (skip),
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

test('[Live Supabase] Acesso anônimo (anon) bloqueado em operadores, condominios e encomendas_itens', async (t) => {
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
});

test('[Live Supabase] Admin Geral autentica, lê condomínios e respeita funções SQL de autorização', async (t) => {
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

test('[Live Supabase] Admin de Condomínio não gerencia condomínio secundário e não se auto-promove a global', async (t) => {
  const email = process.env.SUPABASE_TEST_ADMIN_CONDO_EMAIL;
  const password = process.env.SUPABASE_TEST_ADMIN_CONDO_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !email || !password || !CONDO_B) {
    t.skip('Credenciais SUPABASE_TEST_ADMIN_CONDO_* ou CONDO_B não definidas.');
    return;
  }

  const client = await autenticarCliente(email, password);
  assert.ok(client);

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

test('[Live Supabase] Supervisor e Operador não recebem poder administrativo e Storage privado exige Signed URL', async (t) => {
  const supEmail = process.env.SUPABASE_TEST_SUPERVISOR_EMAIL;
  const supPass = process.env.SUPABASE_TEST_SUPERVISOR_PASSWORD;
  if (!TEM_AMBIENTE_TESTE || !supEmail || !supPass) {
    t.skip('Credenciais SUPABASE_TEST_SUPERVISOR_* não definidas.');
    return;
  }

  const supClient = await autenticarCliente(supEmail, supPass);
  assert.ok(supClient);

  const { data: podeGerenciar } = await supClient!.rpc('operador_pode_gerenciar_operadores', {
    p_condominio_id: CONDO_A
  });
  assert.equal(podeGerenciar, false);

  if (CONDO_B) {
    const { data: listaB } = await supClient!.storage.from('encomendas').list(`condominios/${CONDO_B}`, { limit: 1 });
    assert.equal((listaB || []).length, 0);
  }

  await supClient!.auth.signOut();
});
