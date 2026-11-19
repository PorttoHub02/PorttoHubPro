-- ============================================================================
-- PORTTOHUB PRO — 06_RLS_TABELAS_MULTI_TENANT.sql
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   1. Mantém `proteger_campos_operador()` em SECURITY INVOKER (sem auto-bypass
--      via current_user='postgres'), protegendo `permissoes`, perfil, nível,
--      vínculo Auth, contas inativas e transferência de condomínio.
--   2. Cria `proteger_campos_passe_qr()` em SECURITY INVOKER + trigger na tabela
--      `passes_virtuais_qr` bloqueando alteração direta pelo cliente de
--      `usos_realizados`, `max_usos`, `limite_usos`, `status`, `token`,
--      `token_hash`, `condominio_id`, datas e horários (consumo exclusivo pela
--      RPC `validar_e_consumir_passe_qr` via marcador transacional em
--      `porttohub_internal.passe_qr_tx_autorizacao` ou `service_role`).
--   3. Cria triggers `SECURITY INVOKER` protegendo autoria e carimbos de
--      tempo em `historico_absoluto` e `registros_acesso`.
--   4. Pré-audita tabelas e sequences extras fora da lista canônica das 35
--      tabelas sem alterá-las, e restringe revogação/concessão de privilégios
--      e RLS estritamente às 35 tabelas oficiais e suas sequences vinculadas.
--   5. Substitui políticas das 35 tabelas por políticas RLS granulares por
--      operação (SELECT, INSERT, UPDATE, DELETE) exigindo permissões reais do
--      módulo (`operador_tem_permissao_modulo`) e consistência relacional entre
--      tabelas filhas e pais (sem referências cruzando condomínios).
--
-- PRE-REQUISITOS OBRIGATORIOS:
--   - Ter executado 01, 02, 03, 04 e 05 (e preferencialmente 05B).
-- ============================================================================

BEGIN;

-- 0. PROTECAO DE CAMPOS CRITICOS DE OPERADORES (SECURITY INVOKER: SEM AUTO-BYPASS)
CREATE OR REPLACE FUNCTION public.proteger_campos_operador()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
  v_jwt_role TEXT := lower(trim(COALESCE(NULLIF(current_setting('request.jwt.claim.role', TRUE), ''), '')));
  v_jwt_claims JSONB;
BEGIN
  IF v_jwt_role = '' THEN
    BEGIN
      v_jwt_claims := NULLIF(current_setting('request.jwt.claims', TRUE), '')::jsonb;
      v_jwt_role := lower(trim(COALESCE(v_jwt_claims ->> 'role', '')));
    EXCEPTION WHEN OTHERS THEN
      v_jwt_role := '';
    END;
  END IF;

  -- Bypass permitido APENAS para service_role explícito ou sessão SQL administrativa sem JWT
  IF v_jwt_role = 'service_role'
     OR (current_user IN ('postgres', 'supabase_admin') AND auth.uid() IS NULL) THEN
    RETURN NEW;
  END IF;

  -- Administrador Geral autenticado e ativo com acesso_global_condominios = TRUE
  IF public.operador_tem_acesso_global() THEN
    RETURN NEW;
  END IF;

  -- INSERT por admin_condominio: somente no próprio condomínio principal, sem acesso global / admin_geral
  IF TG_OP = 'INSERT' THEN
    IF NEW.condominio_id IS NULL
       OR NOT public.operador_pode_gerenciar_operadores(NEW.condominio_id::text)
       OR NOT public.operador_tem_permissao_modulo(NEW.condominio_id::text, 'cadastros', 'operadores') THEN
      RAISE EXCEPTION 'Acesso negado: você não tem permissão para cadastrar operadores neste condomínio.';
    END IF;

    IF COALESCE(NEW.acesso_global_condominios, FALSE) = TRUE
       OR lower(COALESCE(NEW.perfil, '')) = 'admin_geral'
       OR COALESCE(NEW.nivel_acesso, 3) = 0 THEN
      RAISE EXCEPTION 'Acesso negado: somente o Administrador Geral pode conceder acesso global ou criar Administrador Geral.';
    END IF;

    -- Gestor local cria o registro sem auth_user_id e vincula via endpoint seguro (service_role)
    IF NEW.auth_user_id IS NOT NULL THEN
      IF NEW.auth_user_id IS DISTINCT FROM auth.uid()
         OR EXISTS (SELECT 1 FROM public.operadores ex WHERE ex.auth_user_id = NEW.auth_user_id)
         OR NOT public.operador_auth_email_corresponde(NEW.auth_user_id, NEW.email) THEN
        RAISE EXCEPTION 'Acesso negado: vínculo auth_user_id deve ser realizado pelo endpoint seguro do servidor.';
      END IF;
    END IF;

    RETURN NEW;
  END IF;

  -- UPDATE do próprio registro: bloqueia auto-elevação de privilégios, permissoes, login, e-mail, auth_user_id e condomínio
  IF OLD.auth_user_id = auth.uid() THEN
    IF COALESCE(OLD.ativo, TRUE) = FALSE THEN
      RAISE EXCEPTION 'Acesso negado: conta inativa não pode ser alterada pelo próprio usuário.';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id
       OR NEW.condominio_id IS DISTINCT FROM OLD.condominio_id
       OR lower(COALESCE(NEW.perfil, '')) IS DISTINCT FROM lower(COALESCE(OLD.perfil, ''))
       OR NEW.funcao IS DISTINCT FROM OLD.funcao
       OR NEW.cargo IS DISTINCT FROM OLD.cargo
       OR NEW.nivel_acesso IS DISTINCT FROM OLD.nivel_acesso
       OR NEW.nivel_acesso_custom_id IS DISTINCT FROM OLD.nivel_acesso_custom_id
       OR COALESCE(NEW.permissoes, '{}'::jsonb) IS DISTINCT FROM COALESCE(OLD.permissoes, '{}'::jsonb)
       OR COALESCE(NEW.acesso_global_condominios, FALSE) IS DISTINCT FROM COALESCE(OLD.acesso_global_condominios, FALSE)
       OR COALESCE(NEW.ativo, TRUE) IS DISTINCT FROM COALESCE(OLD.ativo, TRUE)
       OR NEW.email IS DISTINCT FROM OLD.email
       OR NEW.login IS DISTINCT FROM OLD.login
       OR COALESCE(NEW.exigir_troca_senha, FALSE) IS DISTINCT FROM COALESCE(OLD.exigir_troca_senha, FALSE)
       OR NEW.migrado_auth_em IS DISTINCT FROM OLD.migrado_auth_em
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'Acesso negado: não é permitido alterar os próprios campos administrativos, permissões ou vínculo de autenticação.';
    END IF;

    RETURN NEW;
  END IF;

  -- UPDATE de outro operador: exige que o alvo seja subordinado do mesmo condomínio principal (nunca admin_geral)
  IF COALESCE(OLD.acesso_global_condominios, FALSE) = TRUE
     OR lower(COALESCE(OLD.perfil, '')) = 'admin_geral'
     OR OLD.condominio_id IS NULL
     OR NOT public.operador_pode_gerenciar_operadores(OLD.condominio_id::text)
     OR NOT public.operador_tem_permissao_modulo(OLD.condominio_id::text, 'cadastros', 'editar_operadores') THEN
    RAISE EXCEPTION 'Acesso negado: não é permitido gerenciar este operador.';
  END IF;

  -- Administrador de condomínio não transfere operadores entre condomínios
  IF NEW.condominio_id IS DISTINCT FROM OLD.condominio_id THEN
    RAISE EXCEPTION 'Acesso negado: transferência de operadores entre condomínios exige Administrador Geral.';
  END IF;

  -- Impede concessão de acesso global / admin_geral
  IF COALESCE(NEW.acesso_global_condominios, FALSE) = TRUE
     OR lower(COALESCE(NEW.perfil, '')) = 'admin_geral'
     OR COALESCE(NEW.nivel_acesso, 3) = 0 THEN
    RAISE EXCEPTION 'Acesso negado: somente o Administrador Geral pode conceder privilégios globais.';
  END IF;

  -- Impede alteração direta de auth_user_id pelo navegador; o endpoint /api/admin/operadores/provisionar vincula via service_role
  IF NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id THEN
    IF OLD.auth_user_id IS NOT NULL
       OR NEW.auth_user_id IS NULL
       OR NEW.auth_user_id IS DISTINCT FROM auth.uid()
       OR EXISTS (SELECT 1 FROM public.operadores ex WHERE ex.auth_user_id = NEW.auth_user_id AND ex.id <> OLD.id)
       OR NOT public.operador_auth_email_corresponde(NEW.auth_user_id, NEW.email) THEN
      RAISE EXCEPTION 'Acesso negado: alteração de identidade Auth deve ser feita pelo endpoint seguro do servidor.';
    END IF;
  END IF;

  IF OLD.auth_user_id IS NOT NULL AND NEW.email IS DISTINCT FROM OLD.email THEN
    RAISE EXCEPTION 'Acesso negado: alteração de e-mail vinculado ao Auth exige endpoint seguro ou Administrador Geral.';
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.proteger_campos_operador() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.proteger_campos_operador() TO authenticated, service_role;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'operadores') THEN
    DROP TRIGGER IF EXISTS trg_proteger_campos_operador ON public.operadores;
    CREATE TRIGGER trg_proteger_campos_operador
      BEFORE INSERT OR UPDATE ON public.operadores
      FOR EACH ROW
      EXECUTE FUNCTION public.proteger_campos_operador();
  END IF;
END $$;

-- 0B. PROTECAO DE CAMPOS CRITICOS DE PASSES QR (SECURITY INVOKER)
--     Impede adulteração direta pelo cliente de usos_realizados, max_usos, limite_usos,
--     status, token, condominio_id, datas e horários fora da RPC transacional autorizada.
CREATE SCHEMA IF NOT EXISTS porttohub_internal;
REVOKE ALL ON SCHEMA porttohub_internal FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS porttohub_internal.passe_qr_tx_autorizacao (
  txid BIGINT PRIMARY KEY,
  passe_id UUID NOT NULL,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
REVOKE ALL ON TABLE porttohub_internal.passe_qr_tx_autorizacao FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.proteger_campos_passe_qr()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, auth, pg_catalog
AS $$
DECLARE
  v_jwt_role TEXT := lower(trim(COALESCE(NULLIF(current_setting('request.jwt.claim.role', TRUE), ''), '')));
  v_jwt_claims JSONB;
  v_eh_admin_condo_ou_global BOOLEAN := FALSE;
BEGIN
  IF v_jwt_role = '' THEN
    BEGIN
      v_jwt_claims := NULLIF(current_setting('request.jwt.claims', TRUE), '')::jsonb;
      v_jwt_role := lower(trim(COALESCE(v_jwt_claims ->> 'role', '')));
    EXCEPTION WHEN OTHERS THEN
      v_jwt_role := '';
    END;
  END IF;

  -- Permitido APENAS para:
  -- 1) Backend explícito (service_role)
  -- 2) Sessão SQL administrativa direta no banco (auth.uid() IS NULL)
  IF v_jwt_role = 'service_role'
     OR (current_user IN ('postgres', 'supabase_admin') AND auth.uid() IS NULL) THEN
    RETURN NEW;
  END IF;

  -- 3) Atualização executada internamente pela RPC SECURITY DEFINER validar_e_consumir_passe_qr
  --    (avaliado somente quando current_user já é o owner da RPC, evitando consulta à tabela privada por authenticated)
  IF current_user IN ('postgres', 'supabase_admin') AND TG_OP = 'UPDATE' THEN
    IF EXISTS (
      SELECT 1
      FROM porttohub_internal.passe_qr_tx_autorizacao tx
      WHERE tx.txid = txid_current()
        AND tx.passe_id = OLD.id
        AND tx.criado_em >= NOW() - INTERVAL '5 minutes'
    ) THEN
      RETURN NEW;
    END IF;
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF COALESCE(NEW.usos_realizados, 0) <> 0 THEN
      RAISE EXCEPTION 'Acesso negado: Passe Virtual QR deve iniciar com usos_realizados = 0.';
    END IF;
    IF lower(COALESCE(NEW.status, 'valido')) <> 'valido' THEN
      RAISE EXCEPTION 'Acesso negado: Passe Virtual QR deve ser emitido inicialmente com status valido.';
    END IF;
    IF COALESCE(NEW.max_usos, NEW.limite_usos, 1) < 1 OR COALESCE(NEW.limite_usos, NEW.max_usos, 1) < 1 THEN
      RAISE EXCEPTION 'Limite de usos do Passe Virtual QR deve ser maior ou igual a 1.';
    END IF;
    RETURN NEW;
  END IF;

  -- UPDATE direto por cliente autenticado: bloqueia campos estruturais e de consumo
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.condominio_id IS DISTINCT FROM OLD.condominio_id
     OR NEW.token IS DISTINCT FROM OLD.token
     OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
     OR COALESCE(NEW.usos_realizados, 0) IS DISTINCT FROM COALESCE(OLD.usos_realizados, 0)
     OR COALESCE(NEW.max_usos, 1) IS DISTINCT FROM COALESCE(OLD.max_usos, 1)
     OR COALESCE(NEW.limite_usos, 1) IS DISTINCT FROM COALESCE(OLD.limite_usos, 1)
     OR NEW.criado_em IS DISTINCT FROM OLD.criado_em
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'Acesso negado: usos_realizados, max_usos, limite_usos, token e condominio_id de Passes QR são protegidos contra alteração direta.';
  END IF;

  v_eh_admin_condo_ou_global :=
    public.operador_tem_acesso_global()
    OR (OLD.condominio_id IS NOT NULL AND public.operador_pode_gerenciar_operadores(OLD.condominio_id::text));

  -- Alteração de status fora da RPC: permitida apenas a admin_geral/admin_condominio para cancelar passe ainda 'valido'
  IF lower(COALESCE(NEW.status, '')) IS DISTINCT FROM lower(COALESCE(OLD.status, '')) THEN
    IF NOT (
      v_eh_admin_condo_ou_global
      AND lower(COALESCE(OLD.status, '')) = 'valido'
      AND lower(COALESCE(NEW.status, '')) = 'cancelado'
    ) THEN
      RAISE EXCEPTION 'Acesso negado: alteração direta de status do Passe QR não autorizada; utilize a validação oficial.';
    END IF;
  END IF;

  -- Alteração de validade ou janela de horário: restrita a admin_geral/admin_condominio sobre passe 'valido'
  IF NEW.data_validade IS DISTINCT FROM OLD.data_validade
     OR NEW.data_inicio IS DISTINCT FROM OLD.data_inicio
     OR NEW.data_fim IS DISTINCT FROM OLD.data_fim
     OR NEW.hora_inicio IS DISTINCT FROM OLD.hora_inicio
     OR NEW.hora_fim IS DISTINCT FROM OLD.hora_fim THEN
    IF NOT (v_eh_admin_condo_ou_global AND lower(COALESCE(OLD.status, '')) = 'valido') THEN
      RAISE EXCEPTION 'Acesso negado: somente administradores podem ajustar data ou janela de horário de um Passe QR válido.';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.proteger_campos_passe_qr() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.proteger_campos_passe_qr() TO authenticated, service_role;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'passes_virtuais_qr') THEN
    DROP TRIGGER IF EXISTS trg_proteger_campos_passe_qr ON public.passes_virtuais_qr;
    CREATE TRIGGER trg_proteger_campos_passe_qr
      BEFORE INSERT OR UPDATE ON public.passes_virtuais_qr
      FOR EACH ROW
      EXECUTE FUNCTION public.proteger_campos_passe_qr();
  END IF;
END $$;

-- 0C. PROTECAO DE AUTORIA E INTEGRIDADE EM historico_absoluto E registros_acesso (SECURITY INVOKER)
CREATE OR REPLACE FUNCTION public.proteger_autoria_historico_absoluto()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, auth, pg_catalog
AS $$
DECLARE
  v_jwt_role TEXT := lower(trim(COALESCE(NULLIF(current_setting('request.jwt.claim.role', TRUE), ''), '')));
  v_jwt_claims JSONB;
  v_op RECORD;
  v_op_nome TEXT;
BEGIN
  IF v_jwt_role = '' THEN
    BEGIN
      v_jwt_claims := NULLIF(current_setting('request.jwt.claims', TRUE), '')::jsonb;
      v_jwt_role := lower(trim(COALESCE(v_jwt_claims ->> 'role', '')));
    EXCEPTION WHEN OTHERS THEN
      v_jwt_role := '';
    END;
  END IF;

  IF v_jwt_role = 'service_role'
     OR (current_user IN ('postgres', 'supabase_admin') AND auth.uid() IS NULL) THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.condominio_id IS DISTINCT FROM OLD.condominio_id
       OR NEW.operador_id::text IS DISTINCT FROM OLD.operador_id::text
       OR NEW.operador_nome IS DISTINCT FROM OLD.operador_nome
       OR NEW.operador_login IS DISTINCT FROM OLD.operador_login
       OR NEW.modulo IS DISTINCT FROM OLD.modulo
       OR NEW.acao IS DISTINCT FROM OLD.acao
       OR NEW.descricao IS DISTINCT FROM OLD.descricao
       OR NEW.criado_em IS DISTINCT FROM OLD.criado_em
       OR NEW.data_hora IS DISTINCT FROM OLD.data_hora
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'Acesso negado: registros de auditoria (historico_absoluto) são imutáveis quanto à autoria, conteúdo e carimbo de tempo.';
    END IF;
    RETURN NEW;
  END IF;

  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Acesso negado: autenticação obrigatória para gravar auditoria.';
  END IF;

  SELECT o.id, o.nome, o.login, o.email
  INTO v_op
  FROM public.operadores o
  WHERE o.auth_user_id = auth.uid()
    AND COALESCE(o.ativo, TRUE) = TRUE
  LIMIT 1;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Acesso negado: operador autenticado inativo ou sem vínculo válido para auditoria.';
  END IF;

  IF NOT public.operador_pode_registrar_auditoria(NEW.condominio_id::text, NEW.modulo, NEW.acao) THEN
    RAISE EXCEPTION 'Acesso negado: operador não possui autorização para registrar auditoria no módulo "%" (ação "%").',
      COALESCE(NEW.modulo, ''),
      COALESCE(NEW.acao, '');
  END IF;

  v_op_nome := COALESCE(
    NULLIF(trim(v_op.nome), ''),
    NULLIF(trim(v_op.login), ''),
    NULLIF(trim(v_op.email), ''),
    'Operador Autenticado'
  );

  -- Força autoria real derivada de auth.uid() e carimbos de tempo do servidor
  NEW.operador_id := v_op.id;
  NEW.operador_nome := v_op_nome;
  NEW.operador_login := COALESCE(NULLIF(trim(v_op.login), ''), v_op.email);
  NEW.criado_em := NOW();
  NEW.data_hora := NOW();
  NEW.created_at := NOW();

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.proteger_autoria_historico_absoluto() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.proteger_autoria_historico_absoluto() TO authenticated, service_role;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'historico_absoluto') THEN
    ALTER TABLE public.historico_absoluto
      ADD COLUMN IF NOT EXISTS data_hora TIMESTAMPTZ DEFAULT NOW(),
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();

    DROP TRIGGER IF EXISTS trg_proteger_autoria_historico_absoluto ON public.historico_absoluto;
    CREATE TRIGGER trg_proteger_autoria_historico_absoluto
      BEFORE INSERT OR UPDATE ON public.historico_absoluto
      FOR EACH ROW
      EXECUTE FUNCTION public.proteger_autoria_historico_absoluto();
  END IF;
END $$;

CREATE OR REPLACE FUNCTION public.proteger_autoria_registros_acesso()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, auth, pg_catalog
AS $$
DECLARE
  v_jwt_role TEXT := lower(trim(COALESCE(NULLIF(current_setting('request.jwt.claim.role', TRUE), ''), '')));
  v_jwt_claims JSONB;
  v_op RECORD;
  v_op_nome TEXT;
  v_saida_ja_registrada BOOLEAN := FALSE;
  v_marcando_saida BOOLEAN := FALSE;
BEGIN
  IF v_jwt_role = '' THEN
    BEGIN
      v_jwt_claims := NULLIF(current_setting('request.jwt.claims', TRUE), '')::jsonb;
      v_jwt_role := lower(trim(COALESCE(v_jwt_claims ->> 'role', '')));
    EXCEPTION WHEN OTHERS THEN
      v_jwt_role := '';
    END;
  END IF;

  IF v_jwt_role = 'service_role'
     OR (current_user IN ('postgres', 'supabase_admin') AND auth.uid() IS NULL) THEN
    RETURN NEW;
  END IF;

  -- Permite inserção controlada proveniente da RPC SECURITY DEFINER validar_e_consumir_passe_qr
  IF current_user IN ('postgres', 'supabase_admin') AND TG_OP = 'INSERT' AND NEW.passe_qr_id IS NOT NULL THEN
    IF EXISTS (
      SELECT 1
      FROM porttohub_internal.passe_qr_tx_autorizacao tx
      WHERE tx.txid = txid_current()
        AND tx.passe_id = NEW.passe_qr_id
        AND tx.criado_em >= NOW() - INTERVAL '5 minutes'
    ) THEN
      RETURN NEW;
    END IF;
  END IF;

  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Acesso negado: autenticação obrigatória para manipular registros de acesso.';
  END IF;

  SELECT o.id, o.nome, o.login, o.email
  INTO v_op
  FROM public.operadores o
  WHERE o.auth_user_id = auth.uid()
    AND COALESCE(o.ativo, TRUE) = TRUE
  LIMIT 1;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Acesso negado: operador autenticado inativo ou sem vínculo válido.';
  END IF;

  v_op_nome := COALESCE(
    NULLIF(trim(v_op.nome), ''),
    NULLIF(trim(v_op.login), ''),
    NULLIF(trim(v_op.email), ''),
    'Operador Autenticado'
  );

  IF TG_OP = 'INSERT' THEN
    NEW.operador_entrada_nome := v_op_nome;
    NEW.data_hora := NOW();
    NEW.data_hora_entrada := NOW();
    NEW.created_at := NOW();
    NEW.updated_at := NOW();
    NEW.operador_saida_nome := NULL;
    NEW.data_hora_saida := NULL;
    IF NEW.status IS NULL OR trim(NEW.status) = '' THEN
      NEW.status := 'presente';
    END IF;
    RETURN NEW;
  END IF;

  -- UPDATE: impede alteração de dados históricos de entrada
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.condominio_id IS DISTINCT FROM OLD.condominio_id
     OR NEW.operador_entrada_nome IS DISTINCT FROM OLD.operador_entrada_nome
     OR NEW.data_hora IS DISTINCT FROM OLD.data_hora
     OR NEW.data_hora_entrada IS DISTINCT FROM OLD.data_hora_entrada
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.passe_qr_id IS DISTINCT FROM OLD.passe_qr_id THEN
    RAISE EXCEPTION 'Acesso negado: autoria e horário de entrada de registros_acesso são imutáveis.';
  END IF;

  v_saida_ja_registrada := (
    OLD.data_hora_saida IS NOT NULL
    OR NULLIF(trim(COALESCE(OLD.operador_saida_nome, '')), '') IS NOT NULL
  );

  v_marcando_saida := (
    lower(COALESCE(NEW.status, '')) = 'saiu'
    AND lower(COALESCE(OLD.status, '')) <> 'saiu'
  ) OR (
    NEW.data_hora_saida IS DISTINCT FROM OLD.data_hora_saida
    OR NEW.operador_saida_nome IS DISTINCT FROM OLD.operador_saida_nome
  );

  IF v_saida_ja_registrada THEN
    IF NEW.operador_saida_nome IS DISTINCT FROM OLD.operador_saida_nome
       OR NEW.data_hora_saida IS DISTINCT FROM OLD.data_hora_saida THEN
      RAISE EXCEPTION 'Acesso negado: autoria e horário de saída já registrados não podem ser alterados.';
    END IF;
  ELSIF v_marcando_saida THEN
    NEW.operador_saida_nome := v_op_nome;
    NEW.data_hora_saida := NOW();
  END IF;

  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.proteger_autoria_registros_acesso() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.proteger_autoria_registros_acesso() TO authenticated, service_role;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'registros_acesso') THEN
    DROP TRIGGER IF EXISTS trg_proteger_autoria_registros_acesso ON public.registros_acesso;
    CREATE TRIGGER trg_proteger_autoria_registros_acesso
      BEFORE INSERT OR UPDATE ON public.registros_acesso
      FOR EACH ROW
      EXECUTE FUNCTION public.proteger_autoria_registros_acesso();
  END IF;
END $$;

-- 1. PRE-AUDITORIA + HIGIENIZACAO ESTRITA AS 35 TABELAS CANONICAS E SUAS SEQUENCES
DO $$
DECLARE
  rec RECORD;
  tbl TEXT;
  pol RECORD;
  v_extra_tables TEXT := '';
  v_extra_sequences TEXT := '';
  todas_tabelas TEXT[] := ARRAY[
    'condominios', 'operadores', 'operador_condominios',
    'configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'pontos_acesso',
    'historico_absoluto', 'passes_virtuais_qr', 'registros_acesso',
    'encomendas_itens', 'movimentacao_chaves', 'prestadores_acessos', 'reservas_areas_comuns',
    'moradores', 'entregadores', 'lotes_re', 'custodia', 'materiais_posto',
    'chaves', 'checklist_manutencao', 'chamados_manutencao', 'rondas_setores',
    'rondas_pontos', 'rondas_execucao', 'rondas_registros', 'ocorrencias',
    'passagens_posto', 'prestadores', 'lembretes_portaria', 'bancada_volumes',
    'bancada_conferencias', 'agenda_emergencia', 'areas_comuns', 'blacklist_bloqueios'
  ];
BEGIN
  SELECT COALESCE(string_agg(c.relname, ', ' ORDER BY c.relname), '')
  INTO v_extra_tables
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public'
    AND c.relkind = 'r'
    AND NOT (c.relname = ANY(todas_tabelas));

  IF v_extra_tables <> '' THEN
    RAISE NOTICE 'AVISO (06): Tabelas extras detectadas em public que NAO pertencem as 35 oficiais e serao preservadas intactas (privilegios, RLS e politicas inalterados): %', v_extra_tables;
  END IF;

  SELECT COALESCE(string_agg(s.relname, ', ' ORDER BY s.relname), '')
  INTO v_extra_sequences
  FROM pg_class s
  JOIN pg_namespace ns ON ns.oid = s.relnamespace
  WHERE ns.nspname = 'public'
    AND s.relkind = 'S'
    AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      JOIN pg_class t ON t.oid = d.refobjid
      JOIN pg_namespace nt ON nt.oid = t.relnamespace
      WHERE d.objid = s.oid
        AND d.deptype IN ('a', 'i')
        AND nt.nspname = 'public'
        AND t.relkind = 'r'
        AND t.relname = ANY(todas_tabelas)
    );

  IF v_extra_sequences <> '' THEN
    RAISE NOTICE 'AVISO (06): Sequences nao vinculadas as 35 tabelas oficiais serao preservadas intactas: %', v_extra_sequences;
  END IF;

  FOR rec IN
    SELECT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind = 'r'
      AND c.relname = ANY(todas_tabelas)
  LOOP
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC, anon;', rec.relname);
    EXECUTE format('REVOKE TRUNCATE, TRIGGER, REFERENCES ON TABLE public.%I FROM authenticated;', rec.relname);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO authenticated;', rec.relname);
    EXECUTE format('GRANT ALL ON TABLE public.%I TO service_role;', rec.relname);
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', rec.relname);
  END LOOP;

  FOR rec IN
    SELECT DISTINCT s.relname
    FROM pg_class s
    JOIN pg_namespace ns ON ns.oid = s.relnamespace
    JOIN pg_depend d ON d.objid = s.oid AND d.deptype IN ('a', 'i')
    JOIN pg_class t ON t.oid = d.refobjid
    JOIN pg_namespace nt ON nt.oid = t.relnamespace
    WHERE ns.nspname = 'public'
      AND s.relkind = 'S'
      AND nt.nspname = 'public'
      AND t.relkind = 'r'
      AND t.relname = ANY(todas_tabelas)
  LOOP
    EXECUTE format('REVOKE ALL ON SEQUENCE public.%I FROM PUBLIC, anon;', rec.relname);
    EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE public.%I TO authenticated;', rec.relname);
    EXECUTE format('GRANT ALL ON SEQUENCE public.%I TO service_role;', rec.relname);
  END LOOP;

  -- Remove apenas políticas das 35 tabelas oficiais antes de recriar políticas granulares
  FOREACH tbl IN ARRAY todas_tabelas LOOP
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
      FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = tbl LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I;', pol.policyname, tbl);
      END LOOP;
    END IF;
  END LOOP;
END $$;

-- 2. TABELA condominios
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'condominios') THEN
    CREATE POLICY rls_condominios_select ON public.condominios
      FOR SELECT TO authenticated
      USING (public.operador_pode_acessar_condominio(id::text));

    CREATE POLICY rls_condominios_insert ON public.condominios
      FOR INSERT TO authenticated
      WITH CHECK (public.operador_tem_acesso_global());

    CREATE POLICY rls_condominios_update ON public.condominios
      FOR UPDATE TO authenticated
      USING (
        public.operador_tem_acesso_global()
        OR (
          public.operador_pode_gerenciar_operadores(id::text)
          AND public.operador_tem_permissao_modulo(id::text, 'cadastros', 'configurar_condominio')
        )
      )
      WITH CHECK (
        public.operador_tem_acesso_global()
        OR (
          public.operador_pode_gerenciar_operadores(id::text)
          AND public.operador_tem_permissao_modulo(id::text, 'cadastros', 'configurar_condominio')
        )
      );

    CREATE POLICY rls_condominios_delete ON public.condominios
      FOR DELETE TO authenticated
      USING (public.operador_tem_acesso_global());
  END IF;
END $$;

-- 3. TABELA operadores
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'operadores') THEN
    CREATE POLICY rls_operadores_select ON public.operadores
      FOR SELECT TO authenticated
      USING (
        auth_user_id = auth.uid()
        OR public.operador_tem_acesso_global()
        OR (
          COALESCE(acesso_global_condominios, FALSE) = FALSE
          AND lower(COALESCE(perfil, '')) <> 'admin_geral'
          AND condominio_id IS NOT NULL
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'visualizar_operadores')
        )
      );

    CREATE POLICY rls_operadores_insert ON public.operadores
      FOR INSERT TO authenticated
      WITH CHECK (
        public.operador_tem_acesso_global()
        OR (
          COALESCE(acesso_global_condominios, FALSE) = FALSE
          AND lower(COALESCE(perfil, 'operador')) IN ('admin_condominio', 'supervisor', 'operador', 'sindico')
          AND COALESCE(nivel_acesso, 3) <> 0
          AND condominio_id IS NOT NULL
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'operadores')
        )
      );

    CREATE POLICY rls_operadores_update ON public.operadores
      FOR UPDATE TO authenticated
      USING (
        (auth_user_id = auth.uid() AND COALESCE(ativo, TRUE) = TRUE)
        OR public.operador_tem_acesso_global()
        OR (
          auth_user_id IS DISTINCT FROM auth.uid()
          AND COALESCE(acesso_global_condominios, FALSE) = FALSE
          AND lower(COALESCE(perfil, '')) <> 'admin_geral'
          AND condominio_id IS NOT NULL
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'editar_operadores')
        )
      )
      WITH CHECK (
        public.operador_tem_acesso_global()
        OR public.operador_preserva_proprio_perfil(
          id, perfil, funcao, cargo, nivel_acesso, nivel_acesso_custom_id,
          permissoes, acesso_global_condominios, condominio_id, ativo,
          email, login, exigir_troca_senha, auth_user_id
        )
        OR (
          public.operador_pode_editar_alvo_local(
            id, condominio_id, perfil, nivel_acesso, acesso_global_condominios
          )
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'editar_operadores')
        )
      );

    CREATE POLICY rls_operadores_delete ON public.operadores
      FOR DELETE TO authenticated
      USING (
        public.operador_tem_acesso_global()
        OR (
          auth_user_id IS DISTINCT FROM auth.uid()
          AND COALESCE(acesso_global_condominios, FALSE) = FALSE
          AND lower(COALESCE(perfil, '')) <> 'admin_geral'
          AND condominio_id IS NOT NULL
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'excluir_operadores')
        )
      );
  END IF;
END $$;

DROP FUNCTION IF EXISTS public.operador_preserva_proprio_perfil(UUID, TEXT, INTEGER, TEXT, BOOLEAN, UUID, BOOLEAN, UUID);

-- 4. TABELA operador_condominios
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'operador_condominios') THEN
    CREATE POLICY rls_operador_condominios_select ON public.operador_condominios
      FOR SELECT TO authenticated
      USING (
        operador_id = public.operador_atual_id()
        OR public.operador_tem_acesso_global()
        OR (
          public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'visualizar_operadores')
        )
      );

    CREATE POLICY rls_operador_condominios_insert ON public.operador_condominios
      FOR INSERT TO authenticated
      WITH CHECK (
        public.operador_tem_acesso_global()
        OR (
          operador_id IS DISTINCT FROM public.operador_atual_id()
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'operadores')
          AND EXISTS (
            SELECT 1 FROM public.operadores alvo
            WHERE alvo.id = operador_id
              AND alvo.condominio_id = operador_condominios.condominio_id
              AND COALESCE(alvo.acesso_global_condominios, FALSE) = FALSE
              AND lower(COALESCE(alvo.perfil, '')) <> 'admin_geral'
          )
        )
      );

    CREATE POLICY rls_operador_condominios_update ON public.operador_condominios
      FOR UPDATE TO authenticated
      USING (
        public.operador_tem_acesso_global()
        OR (
          operador_id IS DISTINCT FROM public.operador_atual_id()
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'editar_operadores')
          AND EXISTS (
            SELECT 1 FROM public.operadores alvo
            WHERE alvo.id = operador_id
              AND alvo.condominio_id = operador_condominios.condominio_id
              AND COALESCE(alvo.acesso_global_condominios, FALSE) = FALSE
              AND lower(COALESCE(alvo.perfil, '')) <> 'admin_geral'
          )
        )
      )
      WITH CHECK (
        public.operador_tem_acesso_global()
        OR (
          operador_id IS DISTINCT FROM public.operador_atual_id()
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'editar_operadores')
          AND EXISTS (
            SELECT 1 FROM public.operadores alvo
            WHERE alvo.id = operador_id
              AND alvo.condominio_id = operador_condominios.condominio_id
              AND COALESCE(alvo.acesso_global_condominios, FALSE) = FALSE
              AND lower(COALESCE(alvo.perfil, '')) <> 'admin_geral'
          )
        )
      );

    CREATE POLICY rls_operador_condominios_delete ON public.operador_condominios
      FOR DELETE TO authenticated
      USING (
        public.operador_tem_acesso_global()
        OR (
          operador_id IS DISTINCT FROM public.operador_atual_id()
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'excluir_operadores')
          AND EXISTS (
            SELECT 1 FROM public.operadores alvo
            WHERE alvo.id = operador_id
              AND alvo.condominio_id = operador_condominios.condominio_id
              AND COALESCE(alvo.acesso_global_condominios, FALSE) = FALSE
              AND lower(COALESCE(alvo.perfil, '')) <> 'admin_geral'
          )
        )
      );
  END IF;
END $$;

-- 5. CONFIGURACOES E INFRAESTRUTURA CONDOMINIAL
DO $$
DECLARE
  tbl TEXT;
  tabelas_cfg TEXT[] := ARRAY['configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'agenda_emergencia'];
BEGIN
  FOREACH tbl IN ARRAY tabelas_cfg LOOP
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
      EXECUTE format(
        'CREATE POLICY %I ON public.%I FOR SELECT TO authenticated USING (condominio_id IS NOT NULL AND public.operador_pode_acessar_condominio(condominio_id::text));',
        'rls_' || tbl || '_select', tbl
      );
      EXECUTE format(
        'CREATE POLICY %I ON public.%I FOR INSERT TO authenticated WITH CHECK (condominio_id IS NOT NULL AND (public.operador_tem_acesso_global() OR (public.operador_pode_gerenciar_operadores(condominio_id::text) AND public.operador_tem_permissao_modulo(condominio_id::text, ''cadastros'', ''configurar_condominio''))));',
        'rls_' || tbl || '_insert', tbl
      );
      EXECUTE format(
        'CREATE POLICY %I ON public.%I FOR UPDATE TO authenticated USING (condominio_id IS NOT NULL AND (public.operador_tem_acesso_global() OR (public.operador_pode_gerenciar_operadores(condominio_id::text) AND public.operador_tem_permissao_modulo(condominio_id::text, ''cadastros'', ''configurar_condominio'')))) WITH CHECK (condominio_id IS NOT NULL AND (public.operador_tem_acesso_global() OR (public.operador_pode_gerenciar_operadores(condominio_id::text) AND public.operador_tem_permissao_modulo(condominio_id::text, ''cadastros'', ''configurar_condominio''))));',
        'rls_' || tbl || '_update', tbl
      );
      EXECUTE format(
        'CREATE POLICY %I ON public.%I FOR DELETE TO authenticated USING (condominio_id IS NOT NULL AND (public.operador_tem_acesso_global() OR (public.operador_pode_gerenciar_operadores(condominio_id::text) AND public.operador_tem_permissao_modulo(condominio_id::text, ''cadastros'', ''configurar_condominio''))));',
        'rls_' || tbl || '_delete', tbl
      );
    END IF;
  END LOOP;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'pontos_acesso') THEN
    CREATE POLICY rls_pontos_acesso_select ON public.pontos_acesso
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'visualizar'));

    CREATE POLICY rls_pontos_acesso_insert ON public.pontos_acesso
      FOR INSERT TO authenticated
      WITH CHECK (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'configurar_portoes'));

    CREATE POLICY rls_pontos_acesso_update ON public.pontos_acesso
      FOR UPDATE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'configurar_portoes'))
      WITH CHECK (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'configurar_portoes'));

    CREATE POLICY rls_pontos_acesso_delete ON public.pontos_acesso
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'configurar_portoes'));
  END IF;
END $$;

-- 6. AUDITORIA IMUTAVEL: historico_absoluto
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'historico_absoluto') THEN
    CREATE POLICY rls_historico_absoluto_select ON public.historico_absoluto
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'historico_absoluto', 'visualizar'));

    CREATE POLICY rls_historico_absoluto_insert ON public.historico_absoluto
      FOR INSERT TO authenticated
      WITH CHECK (
        public.operador_atual_id() IS NOT NULL
        AND (
          (condominio_id IS NOT NULL AND public.operador_pode_acessar_condominio(condominio_id::text))
          OR (condominio_id IS NULL AND public.operador_tem_acesso_global())
        )
        AND (operador_id IS NULL OR operador_id::text = public.operador_atual_id()::text)
        AND public.operador_pode_registrar_auditoria(condominio_id::text, modulo, acao)
      );

    CREATE POLICY rls_historico_absoluto_update ON public.historico_absoluto
      FOR UPDATE TO authenticated
      USING (public.operador_tem_acesso_global())
      WITH CHECK (public.operador_tem_acesso_global());

    CREATE POLICY rls_historico_absoluto_delete ON public.historico_absoluto
      FOR DELETE TO authenticated
      USING (
        public.operador_tem_acesso_global()
        OR (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'historico_absoluto', 'limpar_dados'))
      );
  END IF;
END $$;

-- 7. CONTROLE DE ACESSO: passes_virtuais_qr, registros_acesso e blacklist_bloqueios
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'passes_virtuais_qr') THEN
    CREATE POLICY rls_passes_virtuais_qr_select ON public.passes_virtuais_qr
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'visualizar'));

    CREATE POLICY rls_passes_virtuais_qr_insert ON public.passes_virtuais_qr
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'gerar_passe_qr')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'criar')
        )
        AND (
          morador_id IS NULL
          OR EXISTS (
            SELECT 1 FROM public.moradores m
            WHERE m.id = morador_id AND m.condominio_id = passes_virtuais_qr.condominio_id
          )
        )
      );

    CREATE POLICY rls_passes_virtuais_qr_update ON public.passes_virtuais_qr
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'editar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'gerar_passe_qr')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'editar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'gerar_passe_qr')
        )
        AND (
          morador_id IS NULL
          OR EXISTS (
            SELECT 1 FROM public.moradores m
            WHERE m.id = morador_id AND m.condominio_id = passes_virtuais_qr.condominio_id
          )
        )
      );

    CREATE POLICY rls_passes_virtuais_qr_delete ON public.passes_virtuais_qr
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_acesso_global()
          OR (
            public.operador_pode_gerenciar_operadores(condominio_id::text)
            AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'excluir')
          )
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'registros_acesso') THEN
    CREATE POLICY rls_registros_acesso_select ON public.registros_acesso
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'visualizar'));

    CREATE POLICY rls_registros_acesso_insert ON public.registros_acesso
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'liberar_entrada')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'criar')
        )
        AND (passe_qr_id IS NULL OR EXISTS (SELECT 1 FROM public.passes_virtuais_qr p WHERE p.id = passe_qr_id AND p.condominio_id = registros_acesso.condominio_id))
        AND (ponto_acesso_id IS NULL OR EXISTS (SELECT 1 FROM public.pontos_acesso pa WHERE pa.id = ponto_acesso_id AND pa.condominio_id = registros_acesso.condominio_id))
        AND (reserva_area_id IS NULL OR EXISTS (SELECT 1 FROM public.reservas_areas_comuns ra WHERE ra.id = reserva_area_id AND ra.condominio_id = registros_acesso.condominio_id))
        AND (
          pessoa_id IS NULL
          OR (
            NOT EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = pessoa_id AND m.condominio_id IS DISTINCT FROM registros_acesso.condominio_id)
            AND NOT EXISTS (SELECT 1 FROM public.prestadores pr WHERE pr.id = pessoa_id AND pr.condominio_id IS DISTINCT FROM registros_acesso.condominio_id)
          )
        )
      );

    CREATE POLICY rls_registros_acesso_update ON public.registros_acesso
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'registrar_saida')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'registrar_saida')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'editar')
        )
        AND (passe_qr_id IS NULL OR EXISTS (SELECT 1 FROM public.passes_virtuais_qr p WHERE p.id = passe_qr_id AND p.condominio_id = registros_acesso.condominio_id))
        AND (ponto_acesso_id IS NULL OR EXISTS (SELECT 1 FROM public.pontos_acesso pa WHERE pa.id = ponto_acesso_id AND pa.condominio_id = registros_acesso.condominio_id))
        AND (reserva_area_id IS NULL OR EXISTS (SELECT 1 FROM public.reservas_areas_comuns ra WHERE ra.id = reserva_area_id AND ra.condominio_id = registros_acesso.condominio_id))
        AND (
          pessoa_id IS NULL
          OR (
            NOT EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = pessoa_id AND m.condominio_id IS DISTINCT FROM registros_acesso.condominio_id)
            AND NOT EXISTS (SELECT 1 FROM public.prestadores pr WHERE pr.id = pessoa_id AND pr.condominio_id IS DISTINCT FROM registros_acesso.condominio_id)
          )
        )
      );

    CREATE POLICY rls_registros_acesso_delete ON public.registros_acesso
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_acesso_global()
          OR (
            public.operador_pode_gerenciar_operadores(condominio_id::text)
            AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'excluir')
          )
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'blacklist_bloqueios') THEN
    CREATE POLICY rls_blacklist_bloqueios_select ON public.blacklist_bloqueios
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'visualizar'));

    CREATE POLICY rls_blacklist_bloqueios_insert ON public.blacklist_bloqueios
      FOR INSERT TO authenticated
      WITH CHECK (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'bloquear'));

    CREATE POLICY rls_blacklist_bloqueios_update ON public.blacklist_bloqueios
      FOR UPDATE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'bloquear'))
      WITH CHECK (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'bloquear'));

    CREATE POLICY rls_blacklist_bloqueios_delete ON public.blacklist_bloqueios
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_acesso_global()
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'excluir')
        )
      );
  END IF;
END $$;

-- 8. MORADORES, ENCOMENDAS, CUSTODIA, CHAVES, RONDAS, AUTORIZADOS E RESERVAS (COM CONSISTENCIA RELACIONAL)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'moradores') THEN
    CREATE POLICY rls_moradores_select ON public.moradores
      FOR SELECT TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'visualizar_moradores')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'moradores', 'visualizar')
        )
      );

    CREATE POLICY rls_moradores_insert ON public.moradores
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'cadastrar_morador')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'moradores', 'criar')
        )
      );

    CREATE POLICY rls_moradores_update ON public.moradores
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'editar_morador')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'gerenciar_veiculos')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'vincular_tags')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'status_acesso_morador')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'moradores', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'editar_morador')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'gerenciar_veiculos')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'vincular_tags')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'status_acesso_morador')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'moradores', 'editar')
        )
      );

    CREATE POLICY rls_moradores_delete ON public.moradores
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'cadastros', 'excluir_morador')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'moradores', 'excluir')
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'entregadores') THEN
    CREATE POLICY rls_entregadores_select ON public.entregadores
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'visualizar'));
    CREATE POLICY rls_entregadores_insert ON public.entregadores
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'cadastrar_entregador')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'criar')
        )
      );
    CREATE POLICY rls_entregadores_update ON public.entregadores
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'cadastrar_entregador')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'cadastrar_entregador')
        )
      );
    CREATE POLICY rls_entregadores_delete ON public.entregadores
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'lotes_re') THEN
    CREATE POLICY rls_lotes_re_select ON public.lotes_re
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'visualizar'));
    CREATE POLICY rls_lotes_re_insert ON public.lotes_re
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'entrada_lote')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'criar_lote')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'criar')
        )
        AND (entregador_id IS NULL OR EXISTS (SELECT 1 FROM public.entregadores e WHERE e.id = entregador_id AND e.condominio_id = lotes_re.condominio_id))
      );
    CREATE POLICY rls_lotes_re_update ON public.lotes_re
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'triagem')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar_lotes')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'triagem')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar_lotes')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar')
        )
        AND (entregador_id IS NULL OR EXISTS (SELECT 1 FROM public.entregadores e WHERE e.id = entregador_id AND e.condominio_id = lotes_re.condominio_id))
      );
    CREATE POLICY rls_lotes_re_delete ON public.lotes_re
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'excluir_lotes')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'excluir')
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'encomendas_itens') THEN
    CREATE POLICY rls_encomendas_itens_select ON public.encomendas_itens
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'visualizar'));

    CREATE POLICY rls_encomendas_itens_insert ON public.encomendas_itens
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'entrada_lote')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'triagem')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'criar')
        )
        AND (lote_re_id IS NULL OR EXISTS (SELECT 1 FROM public.lotes_re l WHERE l.id = lote_re_id AND l.condominio_id = encomendas_itens.condominio_id))
        AND (morador_id IS NULL OR EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = morador_id AND m.condominio_id = encomendas_itens.condominio_id))
      );

    CREATE POLICY rls_encomendas_itens_update ON public.encomendas_itens
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'triagem')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'baixa')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar_pacote')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'triagem')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'baixa')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar_pacote')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'editar')
        )
        AND (lote_re_id IS NULL OR EXISTS (SELECT 1 FROM public.lotes_re l WHERE l.id = lote_re_id AND l.condominio_id = encomendas_itens.condominio_id))
        AND (morador_id IS NULL OR EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = morador_id AND m.condominio_id = encomendas_itens.condominio_id))
      );

    CREATE POLICY rls_encomendas_itens_delete ON public.encomendas_itens
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'excluir_pacote')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'encomendas', 'excluir')
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'custodia') THEN
    CREATE POLICY rls_custodia_select ON public.custodia
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'custodia', 'visualizar'));
    CREATE POLICY rls_custodia_insert ON public.custodia
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'custodia', 'receber')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'custodia', 'criar')
        )
        AND (morador_id IS NULL OR EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = morador_id AND m.condominio_id = custodia.condominio_id))
      );
    CREATE POLICY rls_custodia_update ON public.custodia
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'custodia', 'baixa')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'custodia', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'custodia', 'baixa')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'custodia', 'editar')
        )
        AND (morador_id IS NULL OR EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = morador_id AND m.condominio_id = custodia.condominio_id))
      );
    CREATE POLICY rls_custodia_delete ON public.custodia
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'custodia', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'chaves') THEN
    CREATE POLICY rls_chaves_select ON public.chaves
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'visualizar'));
    CREATE POLICY rls_chaves_insert ON public.chaves
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'cadastrar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'criar')
        )
      );
    CREATE POLICY rls_chaves_update ON public.chaves
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'emprestar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'devolver')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'cadastrar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'emprestar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'devolver')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'cadastrar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'editar')
        )
      );
    CREATE POLICY rls_chaves_delete ON public.chaves
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'movimentacao_chaves') THEN
    CREATE POLICY rls_movimentacao_chaves_select ON public.movimentacao_chaves
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'visualizar'));

    CREATE POLICY rls_movimentacao_chaves_insert ON public.movimentacao_chaves
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'emprestar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'criar')
        )
        AND (chave_id IS NULL OR EXISTS (SELECT 1 FROM public.chaves c WHERE c.id = chave_id AND c.condominio_id = movimentacao_chaves.condominio_id))
      );

    CREATE POLICY rls_movimentacao_chaves_update ON public.movimentacao_chaves
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'devolver')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'devolver')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'editar')
        )
        AND (chave_id IS NULL OR EXISTS (SELECT 1 FROM public.chaves c WHERE c.id = chave_id AND c.condominio_id = movimentacao_chaves.condominio_id))
      );

    CREATE POLICY rls_movimentacao_chaves_delete ON public.movimentacao_chaves
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'chaves', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'prestadores') THEN
    CREATE POLICY rls_prestadores_select ON public.prestadores
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'visualizar'));
    CREATE POLICY rls_prestadores_insert ON public.prestadores
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'cadastrar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'criar')
        )
      );
    CREATE POLICY rls_prestadores_update ON public.prestadores
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'dar_entrada')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'dar_saida')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'dar_entrada')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'dar_saida')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'editar')
        )
      );
    CREATE POLICY rls_prestadores_delete ON public.prestadores
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'prestadores_acessos') THEN
    CREATE POLICY rls_prestadores_acessos_select ON public.prestadores_acessos
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'visualizar'));

    CREATE POLICY rls_prestadores_acessos_insert ON public.prestadores_acessos
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'dar_entrada')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'cadastrar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'criar')
        )
        AND (prestador_id IS NULL OR EXISTS (SELECT 1 FROM public.prestadores p WHERE p.id = prestador_id AND p.condominio_id = prestadores_acessos.condominio_id))
      );

    CREATE POLICY rls_prestadores_acessos_update ON public.prestadores_acessos
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'dar_saida')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'dar_saida')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'editar')
        )
        AND (prestador_id IS NULL OR EXISTS (SELECT 1 FROM public.prestadores p WHERE p.id = prestador_id AND p.condominio_id = prestadores_acessos.condominio_id))
      );

    CREATE POLICY rls_prestadores_acessos_delete ON public.prestadores_acessos
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'autorizados', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'areas_comuns') THEN
    CREATE POLICY rls_areas_comuns_select ON public.areas_comuns
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'visualizar'));
    CREATE POLICY rls_areas_comuns_insert ON public.areas_comuns
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'gerenciar_areas')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'editar')
        )
      );
    CREATE POLICY rls_areas_comuns_update ON public.areas_comuns
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'gerenciar_areas')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'gerenciar_areas')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'editar')
        )
      );
    CREATE POLICY rls_areas_comuns_delete ON public.areas_comuns
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'gerenciar_areas')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'excluir')
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'reservas_areas_comuns') THEN
    CREATE POLICY rls_reservas_areas_comuns_select ON public.reservas_areas_comuns
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'visualizar'));

    CREATE POLICY rls_reservas_areas_comuns_insert ON public.reservas_areas_comuns
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'criar')
        AND (area_id IS NULL OR EXISTS (SELECT 1 FROM public.areas_comuns a WHERE a.id = area_id AND a.condominio_id = reservas_areas_comuns.condominio_id))
        AND (morador_id IS NULL OR EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = morador_id AND m.condominio_id = reservas_areas_comuns.condominio_id))
      );

    CREATE POLICY rls_reservas_areas_comuns_update ON public.reservas_areas_comuns
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'aprovar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'vistoria')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'cancelar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'aprovar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'vistoria')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'cancelar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'editar')
        )
        AND (area_id IS NULL OR EXISTS (SELECT 1 FROM public.areas_comuns a WHERE a.id = area_id AND a.condominio_id = reservas_areas_comuns.condominio_id))
        AND (morador_id IS NULL OR EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = morador_id AND m.condominio_id = reservas_areas_comuns.condominio_id))
      );

    CREATE POLICY rls_reservas_areas_comuns_delete ON public.reservas_areas_comuns
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'cancelar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'reservas', 'excluir')
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'rondas_setores') THEN
    CREATE POLICY rls_rondas_setores_select ON public.rondas_setores
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'visualizar'));
    CREATE POLICY rls_rondas_setores_insert ON public.rondas_setores
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'setores')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
      );
    CREATE POLICY rls_rondas_setores_update ON public.rondas_setores
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'setores')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'setores')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
      );
    CREATE POLICY rls_rondas_setores_delete ON public.rondas_setores
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'excluir')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'setores')
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'rondas_pontos') THEN
    CREATE POLICY rls_rondas_pontos_select ON public.rondas_pontos
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'visualizar'));
    CREATE POLICY rls_rondas_pontos_insert ON public.rondas_pontos
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'cadastrar_pontos')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
        AND (
          setor_id IS NULL
          OR NOT EXISTS (SELECT 1 FROM public.rondas_setores rs WHERE rs.id = setor_id AND rs.condominio_id IS DISTINCT FROM rondas_pontos.condominio_id)
        )
      );
    CREATE POLICY rls_rondas_pontos_update ON public.rondas_pontos
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'cadastrar_pontos')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'cadastrar_pontos')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
        AND (
          setor_id IS NULL
          OR NOT EXISTS (SELECT 1 FROM public.rondas_setores rs WHERE rs.id = setor_id AND rs.condominio_id IS DISTINCT FROM rondas_pontos.condominio_id)
        )
      );
    CREATE POLICY rls_rondas_pontos_delete ON public.rondas_pontos
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'excluir')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'cadastrar_pontos')
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'rondas_execucao') THEN
    CREATE POLICY rls_rondas_execucao_select ON public.rondas_execucao
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'visualizar'));
    CREATE POLICY rls_rondas_execucao_insert ON public.rondas_execucao
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'iniciar_ronda')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'criar')
        )
      );
    CREATE POLICY rls_rondas_execucao_update ON public.rondas_execucao
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'iniciar_ronda')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'iniciar_ronda')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
      );
    CREATE POLICY rls_rondas_execucao_delete ON public.rondas_execucao
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'rondas_registros') THEN
    CREATE POLICY rls_rondas_registros_select ON public.rondas_registros
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'visualizar'));
    CREATE POLICY rls_rondas_registros_insert ON public.rondas_registros
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'iniciar_ronda')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'criar')
        )
        AND (ronda_id IS NULL OR EXISTS (SELECT 1 FROM public.rondas_execucao re WHERE re.id = ronda_id AND re.condominio_id = rondas_registros.condominio_id))
        AND (ronda_execucao_id IS NULL OR EXISTS (SELECT 1 FROM public.rondas_execucao re2 WHERE re2.id = ronda_execucao_id AND re2.condominio_id = rondas_registros.condominio_id))
        AND (ponto_id IS NULL OR EXISTS (SELECT 1 FROM public.rondas_pontos rp WHERE rp.id = ponto_id AND rp.condominio_id = rondas_registros.condominio_id))
      );
    CREATE POLICY rls_rondas_registros_update ON public.rondas_registros
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'iniciar_ronda')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'iniciar_ronda')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'editar')
        )
        AND (ronda_id IS NULL OR EXISTS (SELECT 1 FROM public.rondas_execucao re WHERE re.id = ronda_id AND re.condominio_id = rondas_registros.condominio_id))
        AND (ronda_execucao_id IS NULL OR EXISTS (SELECT 1 FROM public.rondas_execucao re2 WHERE re2.id = ronda_execucao_id AND re2.condominio_id = rondas_registros.condominio_id))
        AND (ponto_id IS NULL OR EXISTS (SELECT 1 FROM public.rondas_pontos rp WHERE rp.id = ponto_id AND rp.condominio_id = rondas_registros.condominio_id))
      );
    CREATE POLICY rls_rondas_registros_delete ON public.rondas_registros
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'rondas', 'excluir'));
  END IF;
END $$;

-- 9. DEMAIS MODULOS OPERACIONAIS COM CONTROLE FUNCIONAL GRANULAR
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'materiais_posto') THEN
    CREATE POLICY rls_materiais_posto_select ON public.materiais_posto
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'materiais', 'visualizar'));
    CREATE POLICY rls_materiais_posto_insert ON public.materiais_posto
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'materiais', 'cadastrar_equipamentos')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'materiais', 'criar')
        )
      );
    CREATE POLICY rls_materiais_posto_update ON public.materiais_posto
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'materiais', 'alterar_status')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'materiais', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'materiais', 'alterar_status')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'materiais', 'editar')
        )
      );
    CREATE POLICY rls_materiais_posto_delete ON public.materiais_posto
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'materiais', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'checklist_manutencao') THEN
    CREATE POLICY rls_checklist_manutencao_select ON public.checklist_manutencao
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'visualizar'));
    CREATE POLICY rls_checklist_manutencao_insert ON public.checklist_manutencao
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'abrir_os')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'criar')
        )
      );
    CREATE POLICY rls_checklist_manutencao_update ON public.checklist_manutencao
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'concluir')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'concluir')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'editar')
        )
      );
    CREATE POLICY rls_checklist_manutencao_delete ON public.checklist_manutencao
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'chamados_manutencao') THEN
    CREATE POLICY rls_chamados_manutencao_select ON public.chamados_manutencao
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'visualizar'));
    CREATE POLICY rls_chamados_manutencao_insert ON public.chamados_manutencao
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'abrir_os')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'criar')
        )
      );
    CREATE POLICY rls_chamados_manutencao_update ON public.chamados_manutencao
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'concluir')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'concluir')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'editar')
        )
      );
    CREATE POLICY rls_chamados_manutencao_delete ON public.chamados_manutencao
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'manutencao', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'ocorrencias') THEN
    CREATE POLICY rls_ocorrencias_select ON public.ocorrencias
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'visualizar'));
    CREATE POLICY rls_ocorrencias_insert ON public.ocorrencias
      FOR INSERT TO authenticated
      WITH CHECK (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'criar'));
    CREATE POLICY rls_ocorrencias_update ON public.ocorrencias
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'resolver')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'resolver')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'editar')
        )
      );
    CREATE POLICY rls_ocorrencias_delete ON public.ocorrencias
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'passagens_posto') THEN
    CREATE POLICY rls_passagens_posto_select ON public.passagens_posto
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'passagem_posto', 'visualizar'));
    CREATE POLICY rls_passagens_posto_insert ON public.passagens_posto
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'passagem_posto', 'assumir_posto')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'passagem_posto', 'criar')
        )
      );
    CREATE POLICY rls_passagens_posto_update ON public.passagens_posto
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'passagem_posto', 'assumir_posto')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'passagem_posto', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'passagem_posto', 'assumir_posto')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'passagem_posto', 'editar')
        )
      );
    CREATE POLICY rls_passagens_posto_delete ON public.passagens_posto
      FOR DELETE TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'passagem_posto', 'excluir'));
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'lembretes_portaria') THEN
    CREATE POLICY rls_lembretes_portaria_select ON public.lembretes_portaria
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_pode_acessar_condominio(condominio_id::text));
    CREATE POLICY rls_lembretes_portaria_insert ON public.lembretes_portaria
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'liberar_entrada')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'criar')
        )
      );
    CREATE POLICY rls_lembretes_portaria_update ON public.lembretes_portaria
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'liberar_entrada')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'criar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'controle_acesso', 'liberar_entrada')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'ocorrencias', 'criar')
        )
      );
    CREATE POLICY rls_lembretes_portaria_delete ON public.lembretes_portaria
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_acesso_global()
          OR public.operador_pode_gerenciar_operadores(condominio_id::text)
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'bancada_volumes') THEN
    CREATE POLICY rls_bancada_volumes_select ON public.bancada_volumes
      FOR SELECT TO authenticated
      USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'visualizar'));
    CREATE POLICY rls_bancada_volumes_insert ON public.bancada_volumes
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'lancar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'criar')
        )
      );
    CREATE POLICY rls_bancada_volumes_update ON public.bancada_volumes
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'lancar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'baixa')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'lancar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'baixa')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'editar')
        )
      );
    CREATE POLICY rls_bancada_volumes_delete ON public.bancada_volumes
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'zerar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'excluir')
        )
      );
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'bancada_conferencias') THEN
    CREATE POLICY rls_bancada_conferencias_select ON public.bancada_conferencias
      FOR SELECT TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'historico')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'visualizar')
        )
      );
    CREATE POLICY rls_bancada_conferencias_insert ON public.bancada_conferencias
      FOR INSERT TO authenticated
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'zerar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'lancar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'criar')
        )
      );
    CREATE POLICY rls_bancada_conferencias_update ON public.bancada_conferencias
      FOR UPDATE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'zerar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'editar')
        )
      )
      WITH CHECK (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'zerar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'editar')
        )
      );
    CREATE POLICY rls_bancada_conferencias_delete ON public.bancada_conferencias
      FOR DELETE TO authenticated
      USING (
        condominio_id IS NOT NULL
        AND (
          public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'zerar')
          OR public.operador_tem_permissao_modulo(condominio_id::text, 'bancada', 'excluir')
        )
      );
  END IF;
END $$;

COMMIT;

NOTIFY pgrst, 'reload schema';
