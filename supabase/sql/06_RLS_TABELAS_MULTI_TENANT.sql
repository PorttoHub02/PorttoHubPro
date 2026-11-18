-- ============================================================================
-- PORTTOHUB PRO — 06_RLS_TABELAS_MULTI_TENANT.sql
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   Remove qualquer política permissiva USING (true) / WITH CHECK (true) e
--   ativa Row Level Security (RLS) real em todas as tabelas do sistema,
--   garantindo que:
--     1. Usuários anônimos (anon) NÃO tenham acesso a dados operacionais.
--     2. Cada operador autenticado só veja/edite registros dos condomínios
--        aos quais está explicitamente autorizado.
--     3. Apenas administradores com acesso_global_condominios = TRUE possam
--        alterar esse flag ou operar múltiplos condomínios globalmente.
--
-- PRE-REQUISITOS OBRIGATORIOS:
--   - Ter executado 01, 02, 03, 04 e 05.
--   - Ter criado o 1º Administrador Geral em auth.users e vinculado via passo 03.
--
-- ATENCAO: A aplicação faz o bloco abaixo de forma idempotente, ignorando
--   apenas tabelas opcionais que ainda não existam no projeto.
-- ============================================================================

BEGIN;

-- 0. PROTECAO DE CAMPOS CRITICOS VIA TRIGGER (DEFESA EM PROFUNDIDADE COM RLS)
CREATE OR REPLACE FUNCTION public.proteger_campos_operador()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
  -- Operações de manutenção via SQL Editor / migrations ou backend Service Role
  IF current_user IN ('postgres', 'supabase_admin')
     OR COALESCE(auth.role(), '') = 'service_role'
     OR COALESCE(current_setting('request.jwt.claim.role', TRUE), '') = 'service_role' THEN
    RETURN NEW;
  END IF;

  -- Administrador Geral autenticado com acesso_global_condominios = TRUE
  IF public.operador_tem_acesso_global() THEN
    RETURN NEW;
  END IF;

  -- INSERT por admin_condominio: somente no próprio condomínio principal, sem acesso global / admin_geral
  IF TG_OP = 'INSERT' THEN
    IF NEW.condominio_id IS NULL
       OR NOT public.operador_pode_gerenciar_operadores(NEW.condominio_id::text) THEN
      RAISE EXCEPTION 'Acesso negado: você não tem permissão para cadastrar operadores neste condomínio.';
    END IF;

    IF COALESCE(NEW.acesso_global_condominios, FALSE) = TRUE
       OR lower(COALESCE(NEW.perfil, '')) = 'admin_geral'
       OR COALESCE(NEW.nivel_acesso, 3) = 0 THEN
      RAISE EXCEPTION 'Acesso negado: somente o Administrador Geral pode conceder acesso global ou criar Administrador Geral.';
    END IF;

    -- Impede sequestro de auth_user_id arbitrário na inserção; aceita apenas Auth criado com o mesmo e-mail ainda sem vínculo
    IF NEW.auth_user_id IS NOT NULL THEN
      IF EXISTS (
        SELECT 1 FROM public.operadores ex WHERE ex.auth_user_id = NEW.auth_user_id
      ) OR NOT EXISTS (
        SELECT 1
        FROM auth.users u
        WHERE u.id = NEW.auth_user_id
          AND lower(COALESCE(u.email, '')) = lower(trim(COALESCE(NEW.email, '')))
          AND trim(COALESCE(NEW.email, '')) <> ''
      ) THEN
        RAISE EXCEPTION 'Acesso negado: vínculo auth_user_id inválido ou pertencente a outra conta.';
      END IF;
    END IF;

    RETURN NEW;
  END IF;

  -- UPDATE do próprio registro: bloqueia auto-elevação de privilégios, login, e-mail, auth_user_id e condomínio
  IF OLD.auth_user_id = auth.uid() THEN
    IF NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id
       OR NEW.condominio_id IS DISTINCT FROM OLD.condominio_id
       OR lower(COALESCE(NEW.perfil, '')) IS DISTINCT FROM lower(COALESCE(OLD.perfil, ''))
       OR NEW.funcao IS DISTINCT FROM OLD.funcao
       OR NEW.cargo IS DISTINCT FROM OLD.cargo
       OR NEW.nivel_acesso IS DISTINCT FROM OLD.nivel_acesso
       OR NEW.nivel_acesso_custom_id IS DISTINCT FROM OLD.nivel_acesso_custom_id
       OR COALESCE(NEW.acesso_global_condominios, FALSE) IS DISTINCT FROM COALESCE(OLD.acesso_global_condominios, FALSE)
       OR COALESCE(NEW.ativo, TRUE) IS DISTINCT FROM COALESCE(OLD.ativo, TRUE)
       OR NEW.email IS DISTINCT FROM OLD.email
       OR NEW.login IS DISTINCT FROM OLD.login THEN
      RAISE EXCEPTION 'Acesso negado: não é permitido alterar os próprios campos administrativos ou de autenticação.';
    END IF;
    RETURN NEW;
  END IF;

  -- UPDATE de outro operador: exige que o alvo seja subordinado do mesmo condomínio principal (nunca admin_geral)
  IF COALESCE(OLD.acesso_global_condominios, FALSE) = TRUE
     OR lower(COALESCE(OLD.perfil, '')) = 'admin_geral'
     OR OLD.condominio_id IS NULL
     OR NOT public.operador_pode_gerenciar_operadores(OLD.condominio_id::text) THEN
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

  -- Impede substituição de auth_user_id já vinculado; permite primeiro vínculo apenas se corresponder ao Auth do e-mail
  IF NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id THEN
    IF OLD.auth_user_id IS NOT NULL
       OR NEW.auth_user_id IS NULL
       OR EXISTS (SELECT 1 FROM public.operadores ex WHERE ex.auth_user_id = NEW.auth_user_id AND ex.id <> OLD.id)
       OR NOT EXISTS (
         SELECT 1
         FROM auth.users u
         WHERE u.id = NEW.auth_user_id
           AND lower(COALESCE(u.email, '')) = lower(trim(COALESCE(NEW.email, '')))
           AND trim(COALESCE(NEW.email, '')) <> ''
       ) THEN
      RAISE EXCEPTION 'Acesso negado: alteração de identidade Auth não autorizada.';
    END IF;
  END IF;

  IF OLD.auth_user_id IS NOT NULL AND NEW.email IS DISTINCT FROM OLD.email THEN
    RAISE EXCEPTION 'Acesso negado: alteração de e-mail vinculado ao Auth exige endpoint seguro ou Administrador Geral.';
  END IF;

  RETURN NEW;
END;
$$;

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

-- 1. BLOQUEIA ACESSO ANONIMO DIRETO NAS TABELAS MULTI-TENANT
DO $$
DECLARE
  tbl TEXT;
  pol RECORD;
  tabelas_multi_tenant TEXT[] := ARRAY[
    'configuracoes', 'moradores', 'entregadores', 'lotes_re',
    'encomendas_itens', 'locais_armazenamento', 'custodia', 'materiais_posto',
    'chaves', 'movimentacao_chaves', 'checklist_manutencao',
    'chamados_manutencao', 'rondas_pontos', 'rondas_execucao',
    'rondas_registros', 'rondas_setores', 'ocorrencias', 'passagens_posto',
    'prestadores', 'prestadores_acessos', 'lembretes_portaria',
    'bancada_volumes', 'bancada_conferencias', 'historico_absoluto',
    'templates_whatsapp', 'agenda_emergencia', 'areas_comuns',
    'reservas_areas_comuns', 'pontos_acesso', 'registros_acesso',
    'passes_virtuais_qr', 'blacklist_bloqueios'
  ];
BEGIN
  FOREACH tbl IN ARRAY tabelas_multi_tenant LOOP
    IF EXISTS (
      SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = tbl
    ) THEN
      EXECUTE format('REVOKE ALL ON TABLE public.%I FROM anon;', tbl);
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO authenticated;', tbl);
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', tbl);

      FOR pol IN
        SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = tbl
      LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I;', pol.policyname, tbl);
      END LOOP;

      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = tbl AND column_name = 'condominio_id'
      ) THEN
        EXECUTE format(
          'CREATE POLICY %I ON public.%I FOR ALL TO authenticated
           USING (public.operador_pode_acessar_condominio(condominio_id::text))
           WITH CHECK (public.operador_pode_acessar_condominio(condominio_id::text));',
          'rls_tenant_' || tbl,
          tbl
        );
      END IF;
    END IF;
  END LOOP;
END $$;

-- 2. RLS NA TABELA condominios (somente condomínios autorizados ao operador)
DO $$
DECLARE pol RECORD;
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'condominios') THEN
    REVOKE ALL ON TABLE public.condominios FROM anon;
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.condominios TO authenticated;
    ALTER TABLE public.condominios ENABLE ROW LEVEL SECURITY;

    FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = 'condominios' LOOP
      EXECUTE format('DROP POLICY IF EXISTS %I ON public.condominios;', pol.policyname);
    END LOOP;

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
        OR public.operador_pode_gerenciar_operadores(id::text)
      )
      WITH CHECK (
        public.operador_tem_acesso_global()
        OR public.operador_pode_gerenciar_operadores(id::text)
      );

    CREATE POLICY rls_condominios_delete ON public.condominios
      FOR DELETE TO authenticated
      USING (public.operador_tem_acesso_global());
  END IF;
END $$;

-- 3. RLS NA TABELA operadores (auto-leitura; admin_geral global; admin_condominio restrito ao próprio condomínio e sem auto-escalação/transferência)
DO $$
DECLARE pol RECORD;
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'operadores') THEN
    REVOKE ALL ON TABLE public.operadores FROM anon;
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.operadores TO authenticated;
    ALTER TABLE public.operadores ENABLE ROW LEVEL SECURITY;

    FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = 'operadores' LOOP
      EXECUTE format('DROP POLICY IF EXISTS %I ON public.operadores;', pol.policyname);
    END LOOP;

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
        )
      );

    CREATE POLICY rls_operadores_insert ON public.operadores
      FOR INSERT TO authenticated
      WITH CHECK (
        public.operador_tem_acesso_global()
        OR (
          COALESCE(acesso_global_condominios, FALSE) = FALSE
          AND lower(COALESCE(perfil, 'operador')) IN ('admin_condominio', 'supervisor', 'operador')
          AND COALESCE(nivel_acesso, 3) <> 0
          AND condominio_id IS NOT NULL
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
        )
      );

    CREATE POLICY rls_operadores_update ON public.operadores
      FOR UPDATE TO authenticated
      USING (
        auth_user_id = auth.uid()
        OR public.operador_tem_acesso_global()
        OR (
          auth_user_id IS DISTINCT FROM auth.uid()
          AND COALESCE(acesso_global_condominios, FALSE) = FALSE
          AND lower(COALESCE(perfil, '')) <> 'admin_geral'
          AND condominio_id IS NOT NULL
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
        )
      )
      WITH CHECK (
        public.operador_tem_acesso_global()
        OR public.operador_preserva_proprio_perfil(
          id,
          perfil,
          nivel_acesso,
          nivel_acesso_custom_id,
          acesso_global_condominios,
          condominio_id,
          ativo,
          auth_user_id
        )
        OR public.operador_pode_editar_alvo_local(
          id,
          condominio_id,
          perfil,
          nivel_acesso,
          acesso_global_condominios
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
        )
      );
  END IF;
END $$;

-- 4. RLS NA TABELA operador_condominios
DO $$
DECLARE pol RECORD;
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'operador_condominios') THEN
    REVOKE ALL ON TABLE public.operador_condominios FROM anon;
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.operador_condominios TO authenticated;
    ALTER TABLE public.operador_condominios ENABLE ROW LEVEL SECURITY;

    FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = 'operador_condominios' LOOP
      EXECUTE format('DROP POLICY IF EXISTS %I ON public.operador_condominios;', pol.policyname);
    END LOOP;

    CREATE POLICY rls_op_condo_select ON public.operador_condominios
      FOR SELECT TO authenticated
      USING (
        operador_id = public.operador_atual_id()
        OR public.operador_tem_acesso_global()
        OR public.operador_pode_gerenciar_operadores(condominio_id::text)
      );

    CREATE POLICY rls_op_condo_manage ON public.operador_condominios
      FOR ALL TO authenticated
      USING (
        public.operador_tem_acesso_global()
        OR (
          operador_id IS DISTINCT FROM public.operador_atual_id()
          AND public.operador_pode_gerenciar_operadores(condominio_id::text)
          AND EXISTS (
            SELECT 1
            FROM public.operadores alvo
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
          AND EXISTS (
            SELECT 1
            FROM public.operadores alvo
            WHERE alvo.id = operador_id
              AND alvo.condominio_id = operador_condominios.condominio_id
              AND COALESCE(alvo.acesso_global_condominios, FALSE) = FALSE
              AND lower(COALESCE(alvo.perfil, '')) <> 'admin_geral'
          )
        )
      );
  END IF;
END $$;

COMMIT;

NOTIFY pgrst, 'reload schema';
