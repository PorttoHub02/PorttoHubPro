
-- ============================================================================
-- PORTTOHUB PRO — 06_RLS_TABELAS_MULTI_TENANT.sql
-- VERSAO CORRIGIDA — SEGURANCA MULTI-TENANT
-- ============================================================================

BEGIN;

-- ============================================================================
-- 1. PROTECAO DOS CAMPOS CRITICOS DA TABELA OPERADORES
-- ============================================================================

CREATE OR REPLACE FUNCTION public.proteger_campos_operador()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, auth
AS $$
BEGIN

  -- Administrador Geral autenticado
  IF public.operador_tem_acesso_global() THEN
    RETURN NEW;
  END IF;

  -- INSERT: administrador local somente cria operadores
  -- no seu próprio condomínio, sem acesso global.
  IF TG_OP = 'INSERT' THEN

    IF NEW.condominio_id IS NULL
       OR NOT public.operador_pode_gerenciar_operadores(
         NEW.condominio_id::text
       ) THEN
      RAISE EXCEPTION
        'Acesso negado: não pode cadastrar operadores neste condomínio.';
    END IF;

    IF COALESCE(NEW.acesso_global_condominios, FALSE) = TRUE
       OR lower(COALESCE(NEW.perfil, '')) = 'admin_geral'
       OR NEW.auth_user_id IS NOT NULL THEN
      RAISE EXCEPTION
        'Acesso negado: somente o Administrador Geral pode conceder acesso global ou vincular identidades Auth.';
    END IF;

    RETURN NEW;
  END IF;

  -- UPDATE: impede autoelevação
  IF OLD.auth_user_id = auth.uid() THEN

    IF NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id
       OR NEW.condominio_id IS DISTINCT FROM OLD.condominio_id
       OR NEW.perfil IS DISTINCT FROM OLD.perfil
       OR NEW.funcao IS DISTINCT FROM OLD.funcao
       OR NEW.cargo IS DISTINCT FROM OLD.cargo
       OR NEW.nivel_acesso IS DISTINCT FROM OLD.nivel_acesso
       OR NEW.nivel_acesso_custom_id IS DISTINCT FROM OLD.nivel_acesso_custom_id
       OR NEW.acesso_global_condominios IS DISTINCT FROM OLD.acesso_global_condominios
       OR NEW.ativo IS DISTINCT FROM OLD.ativo
       OR NEW.email IS DISTINCT FROM OLD.email
       OR NEW.login IS DISTINCT FROM OLD.login THEN

      RAISE EXCEPTION
        'Acesso negado: não é permitido alterar os próprios campos administrativos ou de autenticação.';
    END IF;

    RETURN NEW;
  END IF;

  -- UPDATE de outro operador:
  -- somente administrador do condomínio de origem.
  IF OLD.condominio_id IS NULL
     OR NOT public.operador_pode_gerenciar_operadores(
       OLD.condominio_id::text
     ) THEN
    RAISE EXCEPTION
      'Acesso negado: não pode gerenciar este operador.';
  END IF;

  -- Administrador local não transfere operadores entre condomínios.
  IF NEW.condominio_id IS DISTINCT FROM OLD.condominio_id THEN
    RAISE EXCEPTION
      'Acesso negado: transferência de operadores entre condomínios exige Administrador Geral.';
  END IF;

  -- Impede alteração de identidade e concessão de privilégios globais.
  IF NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id
     OR NEW.email IS DISTINCT FROM OLD.email
     OR COALESCE(NEW.acesso_global_condominios, FALSE) = TRUE
     OR lower(COALESCE(NEW.perfil, '')) = 'admin_geral' THEN

    RAISE EXCEPTION
      'Acesso negado: somente o Administrador Geral pode alterar identidade ou conceder privilégios globais.';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_proteger_campos_operador
ON public.operadores;

CREATE TRIGGER trg_proteger_campos_operador
BEFORE INSERT OR UPDATE ON public.operadores
FOR EACH ROW
EXECUTE FUNCTION public.proteger_campos_operador();


-- ============================================================================
-- 2. RLS NAS TABELAS OPERACIONAIS MULTI-TENANT
-- ============================================================================

DO $$
DECLARE
  tbl TEXT;
  pol RECORD;

  tabelas_multi_tenant TEXT[] := ARRAY[
    'configuracoes',
    'moradores',
    'entregadores',
    'lotes_re',
    'encomendas_itens',
    'locais_armazenamento',
    'custodia',
    'materiais_posto',
    'chaves',
    'movimentacao_chaves',
    'checklist_manutencao',
    'chamados_manutencao',
    'rondas_pontos',
    'rondas_execucao',
    'rondas_registros',
    'rondas_setores',
    'ocorrencias',
    'passagens_posto',
    'prestadores',
    'prestadores_acessos',
    'lembretes_portaria',
    'bancada_volumes',
    'bancada_conferencias',
    'historico_absoluto',
    'templates_whatsapp',
    'agenda_emergencia',
    'areas_comuns',
    'reservas_areas_comuns',
    'pontos_acesso',
    'registros_acesso',
    'passes_virtuais_qr',
    'blacklist_bloqueios'
  ];

BEGIN

  FOREACH tbl IN ARRAY tabelas_multi_tenant LOOP

    IF EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name = tbl
    ) THEN

     EXECUTE format(
  'REVOKE ALL ON TABLE public.%I FROM anon',
  tbl
);

      EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO authenticated',
        tbl
      );

      EXECUTE format(
        'ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',
        tbl
      );

      FOR pol IN
        SELECT policyname
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = tbl
      LOOP

        EXECUTE format(
          'DROP POLICY IF EXISTS %I ON public.%I',
          pol.policyname,
          tbl
        );

      END LOOP;

      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = tbl
          AND column_name = 'condominio_id'
      ) THEN

        EXECUTE format(
          'CREATE POLICY %I ON public.%I
           FOR ALL TO authenticated
           USING (
             public.operador_pode_acessar_condominio(
               condominio_id::text
             )
           )
           WITH CHECK (
             public.operador_pode_acessar_condominio(
               condominio_id::text
             )
           )',
          'rls_tenant_' || tbl,
          tbl
        );

      END IF;

    END IF;

  END LOOP;

END $$;


-- ============================================================================
-- 3. RLS DA TABELA CONDOMINIOS
-- ============================================================================

DO $$
DECLARE
  pol RECORD;
BEGIN

  REVOKE ALL ON TABLE public.condominios FROM anon;

  GRANT SELECT, INSERT, UPDATE, DELETE
  ON TABLE public.condominios TO authenticated;

  ALTER TABLE public.condominios ENABLE ROW LEVEL SECURITY;

  FOR pol IN
    SELECT policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'condominios'
  LOOP

    EXECUTE format(
      'DROP POLICY IF EXISTS %I ON public.condominios',
      pol.policyname
    );

  END LOOP;

  CREATE POLICY rls_condominios_select
  ON public.condominios
  FOR SELECT TO authenticated
  USING (
    public.operador_pode_acessar_condominio(id::text)
  );

  CREATE POLICY rls_condominios_insert
  ON public.condominios
  FOR INSERT TO authenticated
  WITH CHECK (
    public.operador_tem_acesso_global()
  );

  CREATE POLICY rls_condominios_update
  ON public.condominios
  FOR UPDATE TO authenticated
  USING (
    public.operador_tem_acesso_global()
    OR public.operador_pode_gerenciar_operadores(id::text)
  )
  WITH CHECK (
    public.operador_tem_acesso_global()
    OR public.operador_pode_gerenciar_operadores(id::text)
  );

  CREATE POLICY rls_condominios_delete
  ON public.condominios
  FOR DELETE TO authenticated
  USING (
    public.operador_tem_acesso_global()
  );

END $$;


-- ============================================================================
-- 4. RLS DA TABELA OPERADORES
-- ============================================================================

DO $$
DECLARE
  pol RECORD;
BEGIN

  REVOKE ALL ON TABLE public.operadores FROM anon;

  GRANT SELECT, INSERT, UPDATE, DELETE
  ON TABLE public.operadores TO authenticated;

  ALTER TABLE public.operadores ENABLE ROW LEVEL SECURITY;

  FOR pol IN
    SELECT policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'operadores'
  LOOP

    EXECUTE format(
      'DROP POLICY IF EXISTS %I ON public.operadores',
      pol.policyname
    );

  END LOOP;

  -- Leitura: próprio registro, Administrador Geral
  -- ou administrador do condomínio correspondente.
  CREATE POLICY rls_operadores_select
  ON public.operadores
  FOR SELECT TO authenticated
  USING (
    auth_user_id = auth.uid()
    OR public.operador_tem_acesso_global()
    OR (
      condominio_id IS NOT NULL
      AND public.operador_pode_gerenciar_operadores(
        condominio_id::text
      )
    )
  );

  -- Cadastro: somente Administrador Geral ou administrador local.
  CREATE POLICY rls_operadores_insert
  ON public.operadores
  FOR INSERT TO authenticated
  WITH CHECK (
    public.operador_tem_acesso_global()
    OR (
      condominio_id IS NOT NULL
      AND COALESCE(acesso_global_condominios, FALSE) = FALSE
      AND public.operador_pode_gerenciar_operadores(
        condominio_id::text
      )
    )
  );

  -- Atualização: próprio registro ou gestão autorizada.
  -- A trigger protege os campos administrativos.
  CREATE POLICY rls_operadores_update
  ON public.operadores
  FOR UPDATE TO authenticated
  USING (
    auth_user_id = auth.uid()
    OR public.operador_tem_acesso_global()
    OR (
      condominio_id IS NOT NULL
      AND public.operador_pode_gerenciar_operadores(
        condominio_id::text
      )
    )
  )
  WITH CHECK (
    public.operador_tem_acesso_global()
    OR (
      COALESCE(acesso_global_condominios, FALSE) = FALSE
      AND (
        auth_user_id = auth.uid()
        OR (
          condominio_id IS NOT NULL
          AND public.operador_pode_gerenciar_operadores(
            condominio_id::text
          )
        )
      )
    )
  );

  -- Exclusão: não permite excluir a própria conta.
  CREATE POLICY rls_operadores_delete
  ON public.operadores
  FOR DELETE TO authenticated
  USING (
    public.operador_tem_acesso_global()
    OR (
      auth_user_id IS DISTINCT FROM auth.uid()
      AND COALESCE(acesso_global_condominios, FALSE) = FALSE
      AND condominio_id IS NOT NULL
      AND public.operador_pode_gerenciar_operadores(
        condominio_id::text
      )
    )
  );

END $$;


-- ============================================================================
-- 5. RLS DA TABELA OPERADOR_CONDOMINIOS
-- ============================================================================

DO $$
DECLARE
  pol RECORD;
BEGIN

  REVOKE ALL ON TABLE public.operador_condominios FROM anon;

  GRANT SELECT, INSERT, UPDATE, DELETE
  ON TABLE public.operador_condominios TO authenticated;

  ALTER TABLE public.operador_condominios ENABLE ROW LEVEL SECURITY;

  FOR pol IN
    SELECT policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'operador_condominios'
  LOOP

    EXECUTE format(
      'DROP POLICY IF EXISTS %I ON public.operador_condominios',
      pol.policyname
    );

  END LOOP;

  CREATE POLICY rls_op_condo_select
  ON public.operador_condominios
  FOR SELECT TO authenticated
  USING (
    operador_id = public.operador_atual_id()
    OR public.operador_tem_acesso_global()
    OR public.operador_pode_gerenciar_operadores(
      condominio_id::text
    )
  );

  CREATE POLICY rls_op_condo_manage
  ON public.operador_condominios
  FOR ALL TO authenticated
  USING (
    public.operador_tem_acesso_global()
    OR (
      public.operador_pode_gerenciar_operadores(
        condominio_id::text
      )
      AND EXISTS (
        SELECT 1
        FROM public.operadores alvo
        WHERE alvo.id = operador_id
          AND alvo.condominio_id = operador_condominios.condominio_id
      )
    )
  )
  WITH CHECK (
    public.operador_tem_acesso_global()
    OR (
      public.operador_pode_gerenciar_operadores(
        condominio_id::text
      )
      AND EXISTS (
        SELECT 1
        FROM public.operadores alvo
        WHERE alvo.id = operador_id
          AND alvo.condominio_id = operador_condominios.condominio_id
      )
    )
  );

END $$;


-- ============================================================================
-- 6. FINALIZACAO
-- ============================================================================

COMMIT;

NOTIFY pgrst, 'reload schema';

-- ============================================================================
-- FIM DO ARQUIVO 06
-- ============================================================================
