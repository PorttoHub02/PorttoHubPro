-- ============================================================================
-- PORTTOHUB PRO — 11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql
-- ============================================================================
-- MIGRAÇÃO INCREMENTAL IDEMPOTENTE E NÃO DESTRUTIVA PARA BANCO JÁ IMPLANTADO
-- ============================================================================
-- O QUE ESTE ARQUIVO CORRIGE NO PROJETO SUPABASE EM PRODUÇÃO:
--   0. Pré-checagem obrigatória + pré-auditoria do pg_policies e tabelas fora
--      do catálogo oficial (sem apagar nenhuma tabela nem dado).
--   1. Corrige `operador_auth_email_corresponde(UUID, TEXT)` para impedir
--      enumeração/sondagem de auth.users por usuários comuns autenticados.
--   2. Cria/atualiza `operador_tem_permissao_modulo` espelhando as chaves reais
--      de `src/services/permissoesService.ts` + `operador_preserva_proprio_perfil`
--      + `operador_pode_editar_alvo_local`.
--   3. Corrige o bypass em `validar_e_consumir_passe_qr` (remove exceção via
--      `current_user NOT IN`), exige `v_jwt_role = 'service_role'` quando
--      `auth.uid() IS NULL`, exige permissão `controle_acesso` e define a flag
--      transacional `porttohub.rpc_passe_qr_consumo = '1'`.
--   4. Mantém `proteger_campos_operador()` em SECURITY INVOKER + cria
--      `proteger_campos_passe_qr()` em SECURITY INVOKER na tabela
--      `passes_virtuais_qr` bloqueando adulteração direta de usos/status/token.
--   5. Revoga privilégios excessivos (`PUBLIC`, `anon` e `TRUNCATE`, `TRIGGER`,
--      `REFERENCES` de `authenticated`) em todas as tabelas e sequences.
--   6. Remove políticas antigas APENAS das 35 tabelas canônicas (`todas_tabelas`),
--      sem tocar cegamente em tabelas extras, e recria políticas granulares
--      (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) exigindo permissões por módulo
--      e consistência relacional entre tabelas filhas e pais.
--   7. Garante todas as 8 políticas privadas de Storage (`condominios/{uuid}/...`
--      com `operador_atual_id() IS NOT NULL` e `operadores/{auth.uid()}/...`).
--   8. Valida `chk_passes_qr_usos_limite` (`VALIDATE CONSTRAINT`) quando houver
--      0 violações nos registros existentes (sem apagar dados).
--
-- GARANTIA NÃO DESTRUTIVA:
--   - NÃO executa DROP TABLE, TRUNCATE, DELETE em massa nem reset.
--   - Preserva integralmente o Admin Geral, vínculos e registros existentes.
-- ============================================================================

BEGIN;

-- ============================================================================
-- 0. PRÉ-CHECAGEM E PRÉ-AUDITORIA SEGURA DO AMBIENTE EXISTENTE
-- ============================================================================
DO $$
DECLARE
  v_admin_count INTEGER := 0;
  v_bucket_count INTEGER := 0;
  v_pol_public_count INTEGER := 0;
  v_pol_for_all_count INTEGER := 0;
  v_pol_permissive_count INTEGER := 0;
  v_extra_tables TEXT := '';
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
  IF to_regclass('public.condominios') IS NULL
     OR to_regclass('public.operadores') IS NULL
     OR to_regclass('public.operador_condominios') IS NULL
     OR to_regclass('public.passes_virtuais_qr') IS NULL
     OR to_regclass('public.registros_acesso') IS NULL THEN
    RAISE EXCEPTION 'Pre-requisito nao atendido: execute primeiro a sequencia inicial (01 a 04) antes da migracao 11.';
  END IF;

  SELECT COUNT(*)
  INTO v_admin_count
  FROM public.operadores
  WHERE COALESCE(acesso_global_condominios, FALSE) = TRUE
    AND COALESCE(ativo, TRUE) = TRUE
    AND auth_user_id IS NOT NULL;

  IF v_admin_count < 1 THEN
    RAISE EXCEPTION 'Pre-requisito nao atendido: nenhum admin_geral ativo vinculado ao Auth encontrado. Nenhuma alteracao aplicada.';
  END IF;

  SELECT COUNT(*)
  INTO v_bucket_count
  FROM storage.buckets
  WHERE id = 'encomendas';

  IF v_bucket_count < 1 THEN
    RAISE NOTICE 'Aviso: bucket encomendas sera criado como privado pelo bloco de Storage desta migracao.';
  END IF;

  -- Pré-auditoria explícita em pg_policies antes de qualquer alteração
  SELECT
    COUNT(*),
    COUNT(*) FILTER (WHERE cmd = 'ALL'),
    COUNT(*) FILTER (WHERE COALESCE(qual, '') IN ('true', '(true)') OR COALESCE(with_check, '') IN ('true', '(true)'))
  INTO v_pol_public_count, v_pol_for_all_count, v_pol_permissive_count
  FROM pg_policies
  WHERE schemaname = 'public';

  RAISE NOTICE 'Pre-auditoria pg_policies (public): total=%, FOR_ALL=%, permissivas_true=%',
    v_pol_public_count, v_pol_for_all_count, v_pol_permissive_count;

  SELECT COALESCE(string_agg(c.relname, ', ' ORDER BY c.relname), '')
  INTO v_extra_tables
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public'
    AND c.relkind = 'r'
    AND NOT (c.relname = ANY(todas_tabelas));

  IF v_extra_tables <> '' THEN
    RAISE NOTICE 'AVISO: Existem tabelas fora da lista canonica das 35 tabelas (suas politicas NAO serao removidas cegamente): %', v_extra_tables;
  END IF;
END $$;

-- ============================================================================
-- 1. FUNÇÕES DE AUTORIZAÇÃO, EMAIL SEGURO E PERMISSÃO POR MÓDULO
-- ============================================================================
CREATE OR REPLACE FUNCTION public.operador_atual_id()
RETURNS UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT o.id
  FROM public.operadores o
  WHERE o.auth_user_id = auth.uid()
    AND COALESCE(o.ativo, TRUE) = TRUE
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.operador_tem_acesso_global()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT
    auth.uid() IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM public.operadores o
      WHERE o.auth_user_id = auth.uid()
        AND COALESCE(o.ativo, TRUE) = TRUE
        AND COALESCE(o.acesso_global_condominios, FALSE) = TRUE
    );
$$;

CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT public.operador_tem_acesso_global();
$$;

CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores(p_condominio_id TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT
    auth.uid() IS NOT NULL
    AND p_condominio_id IS NOT NULL
    AND trim(p_condominio_id) <> ''
    AND lower(trim(p_condominio_id)) NOT IN ('todos', 'global', 'null', 'undefined')
    AND EXISTS (
      SELECT 1
      FROM public.operadores o
      WHERE o.auth_user_id = auth.uid()
        AND COALESCE(o.ativo, TRUE) = TRUE
        AND (
          COALESCE(o.acesso_global_condominios, FALSE) = TRUE
          OR (
            lower(COALESCE(o.perfil, '')) IN ('admin_condominio', 'admin_local', 'admin', 'master')
            AND o.condominio_id IS NOT NULL
            AND o.condominio_id::text = trim(p_condominio_id)
          )
        )
    );
$$;

CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores(p_condominio_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT public.operador_pode_gerenciar_operadores(p_condominio_id::text);
$$;

CREATE OR REPLACE FUNCTION public.operador_pode_acessar_condominio(p_condominio_id TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT
    auth.uid() IS NOT NULL
    AND p_condominio_id IS NOT NULL
    AND trim(p_condominio_id) <> ''
    AND lower(trim(p_condominio_id)) NOT IN ('todos', 'global', 'null', 'undefined')
    AND EXISTS (
      SELECT 1
      FROM public.operadores o
      WHERE o.auth_user_id = auth.uid()
        AND COALESCE(o.ativo, TRUE) = TRUE
        AND (
          COALESCE(o.acesso_global_condominios, FALSE) = TRUE
          OR o.condominio_id::text = trim(p_condominio_id)
          OR EXISTS (
            SELECT 1
            FROM public.operador_condominios oc
            WHERE oc.operador_id = o.id
              AND COALESCE(oc.ativo, TRUE) = TRUE
              AND oc.condominio_id::text = trim(p_condominio_id)
          )
        )
    );
$$;

CREATE OR REPLACE FUNCTION public.operador_pode_acessar_condominio(p_condominio_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT public.operador_pode_acessar_condominio(p_condominio_id::text);
$$;

-- Auxiliar protegido: bloqueia sondagem de auth.users por usuários comuns para terceiros
CREATE OR REPLACE FUNCTION public.operador_auth_email_corresponde(
  p_auth_user_id UUID,
  p_email TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, auth
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

  IF p_auth_user_id IS NULL OR trim(COALESCE(p_email, '')) = '' THEN
    RETURN FALSE;
  END IF;

  IF p_auth_user_id IS DISTINCT FROM auth.uid()
     AND v_jwt_role <> 'service_role'
     AND NOT (auth.uid() IS NULL AND session_user IN ('postgres', 'supabase_admin')) THEN
    RETURN FALSE;
  END IF;

  RETURN EXISTS (
    SELECT 1
    FROM auth.users u
    WHERE u.id = p_auth_user_id
      AND lower(COALESCE(u.email, '')) = lower(trim(p_email))
  );
END;
$$;

-- Verificação funcional real de módulo e ação (espelha src/services/permissoesService.ts)
CREATE OR REPLACE FUNCTION public.operador_tem_permissao_modulo(
  p_condominio_id TEXT,
  p_modulo TEXT,
  p_acao TEXT DEFAULT 'visualizar'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  v_condo TEXT := trim(COALESCE(p_condominio_id, ''));
  v_mod TEXT := lower(trim(COALESCE(p_modulo, '')));
  v_acao TEXT := lower(trim(COALESCE(p_acao, 'visualizar')));
  v_op RECORD;
  v_perfil TEXT;
  v_nivel INTEGER;
  v_eh_admin_condo BOOLEAN := FALSE;
  v_eh_supervisor BOOLEAN := FALSE;
  v_eh_sindico BOOLEAN := FALSE;
  v_perm JSONB;
  v_mod_obj JSONB;
  v_cad_obj JSONB;
  v_fallback_acao TEXT := NULL;
BEGIN
  IF auth.uid() IS NULL OR v_condo = '' OR v_mod = '' OR v_acao = '' THEN
    RETURN FALSE;
  END IF;

  IF NOT public.operador_pode_acessar_condominio(v_condo) THEN
    RETURN FALSE;
  END IF;

  SELECT
    o.id,
    o.condominio_id,
    o.perfil,
    o.nivel_acesso,
    o.acesso_global_condominios,
    o.permissoes,
    o.ativo
  INTO v_op
  FROM public.operadores o
  WHERE o.auth_user_id = auth.uid()
    AND COALESCE(o.ativo, TRUE) = TRUE
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN FALSE;
  END IF;

  IF COALESCE(v_op.acesso_global_condominios, FALSE) = TRUE THEN
    RETURN TRUE;
  END IF;

  IF v_mod = 'prestadores' THEN v_mod := 'autorizados'; END IF;
  IF v_mod = 'passagem' THEN v_mod := 'passagem_posto'; END IF;

  v_perfil := lower(trim(COALESCE(v_op.perfil, '')));
  v_nivel := v_op.nivel_acesso;

  v_eh_admin_condo := (v_perfil IN ('admin_condominio', 'admin_local', 'admin', 'master'));
  v_eh_supervisor := (NOT v_eh_admin_condo AND (v_perfil = 'supervisor' OR v_nivel = 2));
  v_eh_sindico := (NOT v_eh_admin_condo AND NOT v_eh_supervisor AND (v_perfil LIKE '%sind%' OR v_nivel = 4));

  IF v_mod = 'materiais' AND v_acao IN ('excluir', 'excluir_equipamento') THEN
    IF NOT v_eh_admin_condo AND NOT v_eh_supervisor AND (COALESCE(v_nivel, 3) >= 3 OR v_perfil IN ('operador', 'porteiro')) THEN
      RETURN FALSE;
    END IF;
  END IF;

  IF v_mod = 'configuracoes' AND v_acao <> 'visualizar' THEN
    RETURN FALSE;
  END IF;

  IF v_mod = 'cadastros' THEN
    IF v_acao IN ('condominios', 'gerenciar_niveis') THEN
      RETURN FALSE;
    END IF;
    IF v_acao IN ('operadores', 'cadastrar_operadores', 'editar_operadores', 'alterar_senha_operador', 'excluir_operadores') THEN
      IF NOT v_eh_admin_condo OR v_op.condominio_id IS NULL OR v_op.condominio_id::text <> v_condo THEN
        RETURN FALSE;
      END IF;
    END IF;
  END IF;

  v_perm := COALESCE(v_op.permissoes, '{}'::jsonb);

  IF v_eh_sindico THEN
    v_mod_obj := COALESCE(
      v_perm -> v_mod,
      CASE
        WHEN v_mod = 'autorizados' THEN v_perm -> 'prestadores'
        WHEN v_mod = 'passagem_posto' THEN v_perm -> 'passagem'
        WHEN v_mod = 'moradores' THEN COALESCE(v_perm -> 'moradores', v_perm -> 'cadastros')
        ELSE NULL
      END
    );

    IF v_mod_obj IS NOT NULL AND jsonb_typeof(v_mod_obj) = 'object' AND lower(COALESCE(v_mod_obj ->> 'visualizar', '')) = 'false' THEN
      RETURN FALSE;
    END IF;

    IF v_mod = 'ocorrencias' THEN
      RETURN v_acao IN ('visualizar', 'criar', 'resolver');
    END IF;

    IF v_acao IN ('visualizar', 'relatorio', 'dossie', 'historico', 'ver_feed', 'ver_metricas', 'exportar_csv', 'visualizar_moradores', 'visualizar_operadores', 'auditoria') THEN
      RETURN TRUE;
    END IF;

    RETURN FALSE;
  END IF;

  IF v_mod = 'moradores' THEN
    v_mod_obj := v_perm -> 'moradores';
    v_cad_obj := v_perm -> 'cadastros';

    IF v_mod_obj IS NOT NULL AND jsonb_typeof(v_mod_obj) = 'object' THEN
      IF lower(COALESCE(v_mod_obj ->> 'visualizar', '')) = 'false' THEN
        RETURN FALSE;
      END IF;
      IF v_acao = 'visualizar' AND v_mod_obj ? 'visualizar' THEN
        RETURN lower(v_mod_obj ->> 'visualizar') = 'true';
      END IF;
      IF v_mod_obj ? v_acao THEN
        RETURN lower(v_mod_obj ->> v_acao) = 'true';
      END IF;
      IF v_acao IN ('adicionar', 'cadastrar', 'criar') THEN
        IF v_mod_obj ? 'adicionar' THEN RETURN lower(v_mod_obj ->> 'adicionar') = 'true'; END IF;
        IF v_mod_obj ? 'criar' THEN RETURN lower(v_mod_obj ->> 'criar') = 'true'; END IF;
        IF v_mod_obj ? 'cadastrar' THEN RETURN lower(v_mod_obj ->> 'cadastrar') = 'true'; END IF;
      END IF;
    END IF;

    IF v_cad_obj IS NOT NULL AND jsonb_typeof(v_cad_obj) = 'object' THEN
      IF lower(COALESCE(v_cad_obj ->> 'visualizar', '')) = 'false' THEN
        RETURN FALSE;
      END IF;
      IF v_acao = 'visualizar' AND v_cad_obj ? 'visualizar_moradores' THEN
        RETURN lower(v_cad_obj ->> 'visualizar_moradores') = 'true';
      END IF;
      IF v_acao IN ('criar', 'adicionar', 'cadastrar') AND (v_cad_obj ? 'cadastrar_morador' OR v_cad_obj ? 'moradores') THEN
        RETURN lower(COALESCE(v_cad_obj ->> 'cadastrar_morador', v_cad_obj ->> 'moradores', 'false')) = 'true';
      END IF;
      IF v_acao = 'editar' AND (v_cad_obj ? 'editar_morador' OR v_cad_obj ? 'moradores') THEN
        RETURN lower(COALESCE(v_cad_obj ->> 'editar_morador', v_cad_obj ->> 'moradores', 'false')) = 'true';
      END IF;
      IF v_acao = 'excluir' AND v_cad_obj ? 'excluir_morador' THEN
        RETURN lower(v_cad_obj ->> 'excluir_morador') = 'true';
      END IF;
    END IF;
  ELSE
    v_mod_obj := COALESCE(
      v_perm -> v_mod,
      CASE
        WHEN v_mod = 'autorizados' THEN v_perm -> 'prestadores'
        WHEN v_mod = 'passagem_posto' THEN v_perm -> 'passagem'
        ELSE NULL
      END
    );

    IF v_mod_obj IS NOT NULL AND jsonb_typeof(v_mod_obj) = 'object' THEN
      IF lower(COALESCE(v_mod_obj ->> 'visualizar', '')) = 'false' THEN
        RETURN FALSE;
      END IF;

      IF v_acao = 'visualizar' THEN
        IF v_mod_obj ? 'visualizar' THEN
          RETURN lower(v_mod_obj ->> 'visualizar') = 'true';
        END IF;
        RETURN TRUE;
      END IF;

      IF v_mod_obj ? v_acao THEN
        RETURN lower(v_mod_obj ->> v_acao) = 'true';
      END IF;

      v_fallback_acao := CASE
        WHEN v_mod = 'encomendas' AND v_acao IN ('entrada_lote', 'criar_lote', 'triagem', 'baixa', 'cadastrar_entregador') THEN 'criar'
        WHEN v_mod = 'encomendas' AND v_acao IN ('editar_pacote', 'editar_lotes') THEN 'editar'
        WHEN v_mod = 'encomendas' AND v_acao IN ('excluir_pacote', 'excluir_lotes') THEN 'excluir'
        WHEN v_mod = 'encomendas' AND v_acao IN ('dossie', 'historico') THEN 'visualizar'
        WHEN v_mod = 'custodia' AND v_acao = 'receber' THEN 'criar'
        WHEN v_mod = 'custodia' AND v_acao = 'baixa' THEN 'editar'
        WHEN v_mod = 'custodia' AND v_acao = 'auditoria' THEN 'visualizar'
        WHEN v_mod = 'chaves' AND v_acao IN ('cadastrar', 'emprestar') THEN 'criar'
        WHEN v_mod = 'chaves' AND v_acao = 'devolver' THEN 'editar'
        WHEN v_mod = 'rondas' AND v_acao IN ('iniciar_ronda', 'cadastrar_pontos') THEN 'criar'
        WHEN v_mod = 'rondas' AND v_acao = 'setores' THEN 'editar'
        WHEN v_mod = 'autorizados' AND v_acao IN ('cadastrar', 'dar_entrada') THEN 'criar'
        WHEN v_mod = 'autorizados' AND v_acao = 'dar_saida' THEN 'editar'
        WHEN v_mod = 'materiais' AND v_acao = 'cadastrar_equipamentos' THEN 'criar'
        WHEN v_mod = 'materiais' AND v_acao = 'alterar_status' THEN 'editar'
        WHEN v_mod = 'manutencao' AND v_acao = 'abrir_os' THEN 'criar'
        WHEN v_mod = 'manutencao' AND v_acao = 'concluir' THEN 'editar'
        WHEN v_mod = 'ocorrencias' AND v_acao = 'resolver' THEN 'editar'
        WHEN v_mod = 'passagem_posto' AND v_acao = 'assumir_posto' THEN 'criar'
        WHEN v_mod = 'passagem_posto' AND v_acao = 'relatorio' THEN 'visualizar'
        WHEN v_mod = 'cadastros' AND v_acao IN ('operadores', 'cadastrar_operadores', 'cadastrar_morador') THEN 'criar'
        WHEN v_mod = 'cadastros' AND v_acao IN ('editar_operadores', 'editar_morador', 'configurar_condominio') THEN 'editar'
        WHEN v_mod = 'cadastros' AND v_acao IN ('excluir_operadores', 'excluir_morador') THEN 'excluir'
        WHEN v_mod = 'cadastros' AND v_acao IN ('visualizar_moradores', 'visualizar_operadores', 'exportar_moradores') THEN 'visualizar'
        WHEN v_mod = 'historico_absoluto' AND v_acao IN ('ver_feed', 'ver_metricas', 'exportar_csv') THEN 'visualizar'
        WHEN v_mod = 'historico_absoluto' AND v_acao = 'limpar_dados' THEN 'excluir'
        WHEN v_mod = 'bancada' AND v_acao = 'lancar' THEN 'criar'
        WHEN v_mod = 'bancada' AND v_acao = 'baixa' THEN 'editar'
        WHEN v_mod = 'bancada' AND v_acao = 'zerar' THEN 'excluir'
        WHEN v_mod = 'bancada' AND v_acao = 'historico' THEN 'visualizar'
        WHEN v_mod = 'reservas' AND v_acao IN ('aprovar', 'gerenciar_areas', 'vistoria') THEN 'editar'
        WHEN v_mod = 'reservas' AND v_acao = 'cancelar' THEN 'excluir'
        WHEN v_mod = 'controle_acesso' AND v_acao IN ('liberar_entrada', 'gerar_passe_qr') THEN 'criar'
        WHEN v_mod = 'controle_acesso' AND v_acao IN ('registrar_saida', 'bloquear', 'configurar_portoes') THEN 'editar'
        ELSE NULL
      END;

      IF v_fallback_acao IS NOT NULL AND v_mod_obj ? v_fallback_acao THEN
        RETURN lower(v_mod_obj ->> v_fallback_acao) = 'true';
      END IF;
    END IF;
  END IF;

  IF v_acao IN ('visualizar', 'historico', 'relatorio', 'ver_feed', 'auditoria', 'visualizar_moradores') THEN
    IF v_mod = 'encomendas' AND v_acao = 'dossie' AND NOT v_eh_admin_condo AND NOT v_eh_supervisor THEN
      RETURN FALSE;
    END IF;
    RETURN TRUE;
  END IF;

  IF v_eh_admin_condo THEN
    IF v_mod = 'historico_absoluto' THEN RETURN FALSE; END IF;
    IF v_mod = 'cadastros' AND v_acao IN ('excluir', 'excluir_morador', 'excluir_operadores', 'condominios', 'gerenciar_niveis') THEN
      RETURN FALSE;
    END IF;
    IF v_mod = 'reservas' AND v_acao = 'cancelar' THEN RETURN TRUE; END IF;
    IF v_acao IN ('excluir', 'excluir_pacote', 'excluir_lotes') THEN
      RETURN v_mod = 'encomendas';
    END IF;
    RETURN TRUE;
  END IF;

  IF v_eh_supervisor THEN
    IF v_mod = 'historico_absoluto' THEN RETURN FALSE; END IF;
    IF v_mod = 'custodia' AND v_acao IN ('editar', 'excluir') THEN RETURN FALSE; END IF;
    IF v_mod = 'rondas' AND v_acao IN ('setores', 'excluir') THEN RETURN FALSE; END IF;
    IF v_mod = 'bancada' AND v_acao IN ('zerar', 'excluir') THEN RETURN FALSE; END IF;
    IF v_mod = 'reservas' AND v_acao IN ('gerenciar_areas', 'excluir') THEN RETURN FALSE; END IF;
    IF v_mod = 'controle_acesso' AND v_acao IN ('configurar_portoes', 'excluir') THEN RETURN FALSE; END IF;
    IF v_mod = 'cadastros' THEN
      RETURN v_acao IN ('visualizar_moradores', 'cadastrar_morador', 'editar_morador', 'gerenciar_veiculos', 'vincular_tags', 'status_acesso_morador', 'exportar_moradores', 'visualizar_operadores', 'criar', 'editar');
    END IF;
    IF v_acao IN ('excluir', 'excluir_pacote', 'excluir_lotes') THEN
      RETURN v_mod = 'encomendas';
    END IF;
    RETURN TRUE;
  END IF;

  IF v_mod = 'encomendas' THEN
    RETURN v_acao IN ('criar', 'entrada_lote', 'criar_lote', 'cadastrar_entregador', 'triagem', 'baixa', 'historico');
  ELSIF v_mod = 'custodia' THEN
    RETURN v_acao IN ('criar', 'receber', 'baixa');
  ELSIF v_mod = 'chaves' THEN
    RETURN v_acao IN ('criar', 'emprestar', 'devolver');
  ELSIF v_mod = 'rondas' THEN
    RETURN v_acao IN ('criar', 'iniciar_ronda');
  ELSIF v_mod = 'autorizados' THEN
    RETURN v_acao IN ('criar', 'cadastrar', 'dar_entrada', 'dar_saida');
  ELSIF v_mod = 'materiais' THEN
    RETURN v_acao = 'alterar_status';
  ELSIF v_mod = 'manutencao' THEN
    RETURN v_acao IN ('criar', 'abrir_os');
  ELSIF v_mod = 'ocorrencias' THEN
    RETURN v_acao = 'criar';
  ELSIF v_mod = 'passagem_posto' THEN
    RETURN v_acao IN ('criar', 'editar', 'assumir_posto');
  ELSIF v_mod = 'cadastros' THEN
    RETURN v_acao IN ('visualizar_moradores', 'cadastrar_morador', 'gerenciar_veiculos');
  ELSIF v_mod = 'moradores' THEN
    RETURN v_acao IN ('criar', 'adicionar', 'cadastrar');
  ELSIF v_mod = 'bancada' THEN
    RETURN v_acao IN ('criar', 'lancar', 'baixa');
  ELSIF v_mod = 'reservas' THEN
    RETURN v_acao IN ('criar', 'vistoria');
  ELSIF v_mod = 'controle_acesso' THEN
    RETURN v_acao IN ('criar', 'editar', 'liberar_entrada', 'registrar_saida', 'gerar_passe_qr');
  END IF;

  RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION public.operador_tem_permissao_modulo(
  p_condominio_id UUID,
  p_modulo TEXT,
  p_acao TEXT DEFAULT 'visualizar'
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT public.operador_tem_permissao_modulo(p_condominio_id::text, p_modulo, p_acao);
$$;

CREATE OR REPLACE FUNCTION public.operador_preserva_proprio_perfil(
  p_id UUID,
  p_perfil TEXT,
  p_funcao TEXT,
  p_cargo TEXT,
  p_nivel INTEGER,
  p_custom_id TEXT,
  p_permissoes JSONB,
  p_global BOOLEAN,
  p_condominio_id UUID,
  p_ativo BOOLEAN,
  p_email TEXT,
  p_login TEXT,
  p_exigir_troca_senha BOOLEAN,
  p_auth_user_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.operadores cur
    WHERE cur.id = p_id
      AND cur.auth_user_id = auth.uid()
      AND COALESCE(cur.ativo, TRUE) = TRUE
      AND lower(COALESCE(cur.perfil, '')) IS NOT DISTINCT FROM lower(COALESCE(p_perfil, ''))
      AND cur.funcao IS NOT DISTINCT FROM p_funcao
      AND cur.cargo IS NOT DISTINCT FROM p_cargo
      AND cur.nivel_acesso IS NOT DISTINCT FROM p_nivel
      AND cur.nivel_acesso_custom_id IS NOT DISTINCT FROM p_custom_id
      AND COALESCE(cur.permissoes, '{}'::jsonb) IS NOT DISTINCT FROM COALESCE(p_permissoes, '{}'::jsonb)
      AND COALESCE(cur.acesso_global_condominios, FALSE) = COALESCE(p_global, FALSE)
      AND cur.condominio_id IS NOT DISTINCT FROM p_condominio_id
      AND COALESCE(cur.ativo, TRUE) = COALESCE(p_ativo, TRUE)
      AND cur.email IS NOT DISTINCT FROM p_email
      AND cur.login IS NOT DISTINCT FROM p_login
      AND COALESCE(cur.exigir_troca_senha, FALSE) = COALESCE(p_exigir_troca_senha, FALSE)
      AND cur.auth_user_id IS NOT DISTINCT FROM p_auth_user_id
  );
$$;

CREATE OR REPLACE FUNCTION public.operador_pode_editar_alvo_local(
  p_id UUID,
  p_novo_condominio_id UUID,
  p_novo_perfil TEXT,
  p_novo_nivel INTEGER,
  p_novo_global BOOLEAN
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT
    p_novo_condominio_id IS NOT NULL
    AND COALESCE(p_novo_global, FALSE) = FALSE
    AND lower(COALESCE(p_novo_perfil, 'operador')) IN ('admin_condominio', 'supervisor', 'operador', 'sindico')
    AND COALESCE(p_novo_nivel, 3) <> 0
    AND public.operador_pode_gerenciar_operadores(p_novo_condominio_id::text)
    AND EXISTS (
      SELECT 1
      FROM public.operadores alvo
      WHERE alvo.id = p_id
        AND alvo.auth_user_id IS DISTINCT FROM auth.uid()
        AND COALESCE(alvo.acesso_global_condominios, FALSE) = FALSE
        AND lower(COALESCE(alvo.perfil, '')) <> 'admin_geral'
        AND alvo.condominio_id IS NOT NULL
        AND alvo.condominio_id = p_novo_condominio_id
    );
$$;

REVOKE ALL ON FUNCTION public.operador_atual_id() FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_tem_acesso_global() FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_pode_gerenciar_operadores() FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_pode_gerenciar_operadores(TEXT) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_pode_gerenciar_operadores(UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_pode_acessar_condominio(TEXT) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_pode_acessar_condominio(UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_auth_email_corresponde(UUID, TEXT) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_tem_permissao_modulo(TEXT, TEXT, TEXT) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_tem_permissao_modulo(UUID, TEXT, TEXT) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_preserva_proprio_perfil(UUID, TEXT, TEXT, TEXT, INTEGER, TEXT, JSONB, BOOLEAN, UUID, BOOLEAN, TEXT, TEXT, BOOLEAN, UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.operador_pode_editar_alvo_local(UUID, UUID, TEXT, INTEGER, BOOLEAN) FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION public.operador_atual_id() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_tem_acesso_global() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_gerenciar_operadores() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_gerenciar_operadores(TEXT) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_gerenciar_operadores(UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_acessar_condominio(TEXT) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_acessar_condominio(UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_auth_email_corresponde(UUID, TEXT) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_tem_permissao_modulo(TEXT, TEXT, TEXT) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_tem_permissao_modulo(UUID, TEXT, TEXT) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_preserva_proprio_perfil(UUID, TEXT, TEXT, TEXT, INTEGER, TEXT, JSONB, BOOLEAN, UUID, BOOLEAN, TEXT, TEXT, BOOLEAN, UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_editar_alvo_local(UUID, UUID, TEXT, INTEGER, BOOLEAN) TO authenticated, service_role;

-- ============================================================================
-- 2. RPC TRANSACIONAL DO PASSE VIRTUAL QR (SEM BYPASS POR current_user)
-- ============================================================================
CREATE OR REPLACE FUNCTION public.validar_e_consumir_passe_qr(
  p_condominio_id UUID,
  p_token TEXT,
  p_consumir BOOLEAN DEFAULT FALSE,
  p_ponto_acesso TEXT DEFAULT 'Portaria Principal (Pedestres)',
  p_operador_nome TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  v_passe RECORD;
  v_operador RECORD;
  v_operador_nome TEXT;
  v_jwt_role TEXT := lower(trim(COALESCE(NULLIF(current_setting('request.jwt.claim.role', TRUE), ''), '')));
  v_jwt_claims JSONB;
  v_token_limpo TEXT := upper(trim(COALESCE(p_token, '')));
  v_raw_limpo TEXT := trim(COALESCE(p_token, ''));
  v_agora_br TIMESTAMP := NOW() AT TIME ZONE 'America/Sao_Paulo';
  v_hoje_br DATE := (NOW() AT TIME ZONE 'America/Sao_Paulo')::date;
  v_hora_br TIME := (NOW() AT TIME ZONE 'America/Sao_Paulo')::time;
  v_max_usos INTEGER;
  v_usos_atuais INTEGER;
  v_novos_usos INTEGER;
  v_novo_status TEXT;
  v_hora_inicio TIME;
  v_hora_fim TIME;
  v_registro_id UUID;
BEGIN
  IF v_jwt_role = '' THEN
    BEGIN
      v_jwt_claims := NULLIF(current_setting('request.jwt.claims', TRUE), '')::jsonb;
      v_jwt_role := lower(trim(COALESCE(v_jwt_claims ->> 'role', '')));
    EXCEPTION WHEN OTHERS THEN
      v_jwt_role := '';
    END;
  END IF;

  IF auth.uid() IS NULL THEN
    IF v_jwt_role <> 'service_role' THEN
      RETURN jsonb_build_object(
        'valido', FALSE,
        'motivo', 'Autenticação obrigatória para validar ou consumir Passe Virtual.'
      );
    END IF;
    v_operador_nome := COALESCE(NULLIF(trim(p_operador_nome), ''), 'Sistema');
  ELSE
    SELECT o.id, o.nome, o.login, o.email
    INTO v_operador
    FROM public.operadores o
    WHERE o.auth_user_id = auth.uid()
      AND COALESCE(o.ativo, TRUE) = TRUE
    LIMIT 1;

    IF NOT FOUND THEN
      RETURN jsonb_build_object(
        'valido', FALSE,
        'motivo', 'Operador autenticado inativo ou sem vínculo válido.'
      );
    END IF;

    IF p_condominio_id IS NULL OR NOT public.operador_pode_acessar_condominio(p_condominio_id::text) THEN
      RETURN jsonb_build_object(
        'valido', FALSE,
        'motivo', 'Acesso negado: operador não autorizado para este condomínio.'
      );
    END IF;

    IF NOT public.operador_tem_permissao_modulo(
      p_condominio_id::text,
      'controle_acesso',
      CASE WHEN COALESCE(p_consumir, FALSE) THEN 'liberar_entrada' ELSE 'visualizar' END
    ) THEN
      RETURN jsonb_build_object(
        'valido', FALSE,
        'motivo', 'Acesso negado: operador sem permissão no módulo Controle de Acesso.'
      );
    END IF;

    v_operador_nome := COALESCE(
      NULLIF(trim(v_operador.nome), ''),
      NULLIF(trim(v_operador.login), ''),
      NULLIF(trim(v_operador.email), ''),
      'Operador Autenticado'
    );
  END IF;

  IF p_condominio_id IS NULL THEN
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', 'Condomínio do Passe Virtual não informado.'
    );
  END IF;

  IF v_token_limpo = '' THEN
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', 'Código do Passe Virtual não informado.'
    );
  END IF;

  SELECT *
  INTO v_passe
  FROM public.passes_virtuais_qr
  WHERE condominio_id = p_condominio_id
    AND (upper(trim(token)) = v_token_limpo OR id::text = v_raw_limpo)
  LIMIT 1
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', 'Passe Virtual não encontrado neste condomínio.'
    );
  END IF;

  IF lower(COALESCE(v_passe.status, '')) <> 'valido' THEN
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', format('Passe está marcado como %s.', upper(COALESCE(v_passe.status, 'INDISPONIVEL'))),
      'passe', to_jsonb(v_passe)
    );
  END IF;

  IF v_passe.data_validade IS NOT NULL AND v_passe.data_validade < v_hoje_br THEN
    PERFORM set_config('porttohub.rpc_passe_qr_consumo', '1', TRUE);
    UPDATE public.passes_virtuais_qr
    SET status = 'expirado', updated_at = NOW()
    WHERE id = v_passe.id;
    PERFORM set_config('porttohub.rpc_passe_qr_consumo', '', TRUE);
    v_passe.status := 'expirado';
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', format('Passe expirou na data %s.', v_passe.data_validade),
      'passe', to_jsonb(v_passe)
    );
  END IF;

  IF v_passe.data_validade IS NOT NULL AND v_passe.data_validade > v_hoje_br THEN
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', format('Passe válido somente na data %s.', v_passe.data_validade),
      'passe', to_jsonb(v_passe)
    );
  END IF;

  BEGIN
    v_hora_inicio := COALESCE(NULLIF(trim(v_passe.hora_inicio), ''), '00:00')::time;
    v_hora_fim := COALESCE(NULLIF(trim(v_passe.hora_fim), ''), '23:59')::time;
    IF v_hora_br < v_hora_inicio OR v_hora_br > v_hora_fim THEN
      RETURN jsonb_build_object(
        'valido', FALSE,
        'motivo', format('Fora da janela de horário autorizada (%s às %s — agora %s BRT).',
          to_char(v_hora_inicio, 'HH24:MI'),
          to_char(v_hora_fim, 'HH24:MI'),
          to_char(v_agora_br, 'HH24:MI')
        ),
        'passe', to_jsonb(v_passe)
      );
    END IF;
  EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', 'Janela de horário configurada no passe é inválida.',
      'passe', to_jsonb(v_passe)
    );
  END;

  v_max_usos := GREATEST(1, COALESCE(v_passe.max_usos, v_passe.limite_usos, 1));
  v_usos_atuais := GREATEST(0, COALESCE(v_passe.usos_realizados, 0));

  IF v_usos_atuais >= v_max_usos THEN
    PERFORM set_config('porttohub.rpc_passe_qr_consumo', '1', TRUE);
    UPDATE public.passes_virtuais_qr
    SET status = 'utilizado', updated_at = NOW()
    WHERE id = v_passe.id;
    PERFORM set_config('porttohub.rpc_passe_qr_consumo', '', TRUE);
    v_passe.status := 'utilizado';
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', 'Limite de utilizações deste passe já foi atingido.',
      'passe', to_jsonb(v_passe)
    );
  END IF;

  IF NOT COALESCE(p_consumir, FALSE) THEN
    RETURN jsonb_build_object(
      'valido', TRUE,
      'passe', to_jsonb(v_passe)
    );
  END IF;

  v_novos_usos := v_usos_atuais + 1;
  v_novo_status := CASE WHEN v_novos_usos >= v_max_usos THEN 'utilizado' ELSE 'valido' END;

  PERFORM set_config('porttohub.rpc_passe_qr_consumo', '1', TRUE);
  UPDATE public.passes_virtuais_qr
  SET
    usos_realizados = v_novos_usos,
    status = v_novo_status,
    updated_at = NOW()
  WHERE id = v_passe.id
  RETURNING * INTO v_passe;
  PERFORM set_config('porttohub.rpc_passe_qr_consumo', '', TRUE);

  INSERT INTO public.registros_acesso (
    condominio_id,
    tipo,
    nome,
    documento,
    unidade_bloco,
    morador_responsavel,
    ponto_acesso_entrada,
    data_hora_entrada,
    status,
    operador_entrada_nome,
    observacoes,
    passe_qr_id
  ) VALUES (
    p_condominio_id,
    CASE WHEN v_passe.tipo = 'festa_convidado' THEN 'convidado_evento' ELSE COALESCE(NULLIF(v_passe.tipo, ''), 'visitante') END,
    v_passe.visitante_nome,
    COALESCE(v_passe.visitante_documento, v_passe.visitante_doc, ''),
    v_passe.unidade_bloco,
    v_passe.morador_nome,
    COALESCE(NULLIF(trim(p_ponto_acesso), ''), 'Portaria Principal (Pedestres)'),
    NOW(),
    'presente',
    v_operador_nome,
    format('Liberado via Passe QR (%s) [Uso %s/%s] - %s', v_passe.token, v_novos_usos, v_max_usos, COALESCE(v_passe.observacoes, '')),
    v_passe.id
  )
  RETURNING id INTO v_registro_id;

  RETURN jsonb_build_object(
    'valido', TRUE,
    'consumido', TRUE,
    'registro_id', v_registro_id,
    'registro', (SELECT to_jsonb(r) FROM public.registros_acesso r WHERE r.id = v_registro_id),
    'passe', to_jsonb(v_passe)
  );
END;
$$;

REVOKE ALL ON FUNCTION public.validar_e_consumir_passe_qr(UUID, TEXT, BOOLEAN, TEXT, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.validar_e_consumir_passe_qr(UUID, TEXT, BOOLEAN, TEXT, TEXT) TO authenticated, service_role;

-- ============================================================================
-- 3. TRIGGERS DE PROTEÇÃO EM MODO SECURITY INVOKER (OPERADORES + PASSES QR)
-- ============================================================================
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

  IF v_jwt_role = 'service_role'
     OR (current_user IN ('postgres', 'supabase_admin') AND auth.uid() IS NULL) THEN
    RETURN NEW;
  END IF;

  IF public.operador_tem_acesso_global() THEN
    RETURN NEW;
  END IF;

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

    IF NEW.auth_user_id IS NOT NULL THEN
      IF NEW.auth_user_id IS DISTINCT FROM auth.uid()
         OR EXISTS (SELECT 1 FROM public.operadores ex WHERE ex.auth_user_id = NEW.auth_user_id)
         OR NOT public.operador_auth_email_corresponde(NEW.auth_user_id, NEW.email) THEN
        RAISE EXCEPTION 'Acesso negado: vínculo auth_user_id deve ser realizado pelo endpoint seguro do servidor.';
      END IF;
    END IF;

    RETURN NEW;
  END IF;

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

  IF COALESCE(OLD.acesso_global_condominios, FALSE) = TRUE
     OR lower(COALESCE(OLD.perfil, '')) = 'admin_geral'
     OR OLD.condominio_id IS NULL
     OR NOT public.operador_pode_gerenciar_operadores(OLD.condominio_id::text)
     OR NOT public.operador_tem_permissao_modulo(OLD.condominio_id::text, 'cadastros', 'editar_operadores') THEN
    RAISE EXCEPTION 'Acesso negado: não é permitido gerenciar este operador.';
  END IF;

  IF NEW.condominio_id IS DISTINCT FROM OLD.condominio_id THEN
    RAISE EXCEPTION 'Acesso negado: transferência de operadores entre condomínios exige Administrador Geral.';
  END IF;

  IF COALESCE(NEW.acesso_global_condominios, FALSE) = TRUE
     OR lower(COALESCE(NEW.perfil, '')) = 'admin_geral'
     OR COALESCE(NEW.nivel_acesso, 3) = 0 THEN
    RAISE EXCEPTION 'Acesso negado: somente o Administrador Geral pode conceder privilégios globais.';
  END IF;

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

DROP TRIGGER IF EXISTS trg_proteger_campos_operador ON public.operadores;
CREATE TRIGGER trg_proteger_campos_operador
  BEFORE INSERT OR UPDATE ON public.operadores
  FOR EACH ROW
  EXECUTE FUNCTION public.proteger_campos_operador();

CREATE OR REPLACE FUNCTION public.proteger_campos_passe_qr()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
  v_jwt_role TEXT := lower(trim(COALESCE(NULLIF(current_setting('request.jwt.claim.role', TRUE), ''), '')));
  v_jwt_claims JSONB;
  v_rpc_consumo TEXT := COALESCE(NULLIF(current_setting('porttohub.rpc_passe_qr_consumo', TRUE), ''), '');
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

  IF v_jwt_role = 'service_role'
     OR (current_user IN ('postgres', 'supabase_admin') AND auth.uid() IS NULL)
     OR (current_user IN ('postgres', 'supabase_admin') AND v_rpc_consumo = '1') THEN
    RETURN NEW;
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

  IF lower(COALESCE(NEW.status, '')) IS DISTINCT FROM lower(COALESCE(OLD.status, '')) THEN
    IF NOT (
      v_eh_admin_condo_ou_global
      AND lower(COALESCE(OLD.status, '')) = 'valido'
      AND lower(COALESCE(NEW.status, '')) = 'cancelado'
    ) THEN
      RAISE EXCEPTION 'Acesso negado: alteração direta de status do Passe QR não autorizada; utilize a validação oficial.';
    END IF;
  END IF;

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

DROP TRIGGER IF EXISTS trg_proteger_campos_passe_qr ON public.passes_virtuais_qr;
CREATE TRIGGER trg_proteger_campos_passe_qr
  BEFORE INSERT OR UPDATE ON public.passes_virtuais_qr
  FOR EACH ROW
  EXECUTE FUNCTION public.proteger_campos_passe_qr();

-- ============================================================================
-- 4. HIGIENIZAÇÃO DE PRIVILÉGIOS E DROP APENAS NAS 35 TABELAS CANÔNICAS
-- ============================================================================
DO $$
DECLARE
  rec RECORD;
  tbl TEXT;
  pol RECORD;
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
  FOR rec IN
    SELECT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
  LOOP
    EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC, anon;', rec.relname);
    EXECUTE format('REVOKE TRUNCATE, TRIGGER, REFERENCES ON TABLE public.%I FROM authenticated;', rec.relname);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO authenticated;', rec.relname);
    EXECUTE format('GRANT ALL ON TABLE public.%I TO service_role;', rec.relname);
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', rec.relname);
  END LOOP;

  FOR rec IN
    SELECT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'S'
  LOOP
    EXECUTE format('REVOKE ALL ON SEQUENCE public.%I FROM PUBLIC, anon;', rec.relname);
    EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE public.%I TO authenticated;', rec.relname);
    EXECUTE format('GRANT ALL ON SEQUENCE public.%I TO service_role;', rec.relname);
  END LOOP;

  -- Remove políticas somente das 35 tabelas oficiais (preserva qualquer tabela auxiliar externa)
  FOREACH tbl IN ARRAY todas_tabelas LOOP
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
      FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = tbl LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I;', pol.policyname, tbl);
      END LOOP;
    END IF;
  END LOOP;
END $$;

-- 4.1 condominios
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

-- 4.2 operadores
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

DROP FUNCTION IF EXISTS public.operador_preserva_proprio_perfil(UUID, TEXT, INTEGER, TEXT, BOOLEAN, UUID, BOOLEAN, UUID);

-- 4.3 operador_condominios
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

-- 4.4 Tabelas de configuração e infraestrutura
DO $$
DECLARE
  tbl TEXT;
  tabelas_cfg TEXT[] := ARRAY['configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'agenda_emergencia'];
BEGIN
  FOREACH tbl IN ARRAY tabelas_cfg LOOP
    IF to_regclass('public.' || tbl) IS NOT NULL THEN
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

-- 4.5 historico_absoluto
CREATE POLICY rls_historico_absoluto_select ON public.historico_absoluto
  FOR SELECT TO authenticated
  USING (condominio_id IS NOT NULL AND public.operador_tem_permissao_modulo(condominio_id::text, 'historico_absoluto', 'visualizar'));

CREATE POLICY rls_historico_absoluto_insert ON public.historico_absoluto
  FOR INSERT TO authenticated
  WITH CHECK (condominio_id IS NOT NULL AND public.operador_pode_acessar_condominio(condominio_id::text));

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

-- 4.6 controle de acesso: passes_virtuais_qr, registros_acesso, blacklist_bloqueios
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
    AND (morador_id IS NULL OR EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = morador_id AND m.condominio_id = passes_virtuais_qr.condominio_id))
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
    AND (morador_id IS NULL OR EXISTS (SELECT 1 FROM public.moradores m WHERE m.id = morador_id AND m.condominio_id = passes_virtuais_qr.condominio_id))
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

-- 4.7 Moradores, encomendas, custodia, chaves, autorizados, reservas e rondas
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

DO $$
BEGIN
  IF to_regclass('public.custodia') IS NOT NULL THEN
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

  IF to_regclass('public.chaves') IS NOT NULL THEN
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

  IF to_regclass('public.movimentacao_chaves') IS NOT NULL THEN
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

  IF to_regclass('public.prestadores') IS NOT NULL THEN
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

  IF to_regclass('public.prestadores_acessos') IS NOT NULL THEN
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

  IF to_regclass('public.areas_comuns') IS NOT NULL THEN
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

  IF to_regclass('public.reservas_areas_comuns') IS NOT NULL THEN
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

  IF to_regclass('public.rondas_setores') IS NOT NULL THEN
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

  IF to_regclass('public.rondas_pontos') IS NOT NULL THEN
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

  IF to_regclass('public.rondas_execucao') IS NOT NULL THEN
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

  IF to_regclass('public.rondas_registros') IS NOT NULL THEN
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

  IF to_regclass('public.materiais_posto') IS NOT NULL THEN
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

  IF to_regclass('public.checklist_manutencao') IS NOT NULL THEN
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

  IF to_regclass('public.chamados_manutencao') IS NOT NULL THEN
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

  IF to_regclass('public.ocorrencias') IS NOT NULL THEN
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

  IF to_regclass('public.passagens_posto') IS NOT NULL THEN
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

  IF to_regclass('public.lembretes_portaria') IS NOT NULL THEN
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

  IF to_regclass('public.bancada_volumes') IS NOT NULL THEN
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

  IF to_regclass('public.bancada_conferencias') IS NOT NULL THEN
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

-- ============================================================================
-- 5. STORAGE PRIVADO: BUCKET 'encomendas' E TODAS AS 8 POLÍTICAS OFICIAIS
-- ============================================================================
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'encomendas',
  'encomendas',
  FALSE,
  10485760,
  ARRAY['image/jpeg', 'image/png', 'image/webp']
)
ON CONFLICT (id) DO UPDATE
SET
  public = FALSE,
  file_size_limit = 10485760,
  allowed_mime_types = ARRAY['image/jpeg', 'image/png', 'image/webp'];

DROP POLICY IF EXISTS "Permitir_upload_publico_encomendas" ON storage.objects;
DROP POLICY IF EXISTS "Permitir_leitura_publica_encomendas" ON storage.objects;
DROP POLICY IF EXISTS "Permitir_update_publico_encomendas" ON storage.objects;
DROP POLICY IF EXISTS "Permitir_delete_publico_encomendas" ON storage.objects;
DROP POLICY IF EXISTS "porttohub_storage_select" ON storage.objects;
DROP POLICY IF EXISTS "porttohub_storage_insert" ON storage.objects;
DROP POLICY IF EXISTS "porttohub_storage_update" ON storage.objects;
DROP POLICY IF EXISTS "porttohub_storage_delete" ON storage.objects;
DROP POLICY IF EXISTS "porttohub_storage_operadores_select" ON storage.objects;
DROP POLICY IF EXISTS "porttohub_storage_operadores_insert" ON storage.objects;
DROP POLICY IF EXISTS "porttohub_storage_operadores_update" ON storage.objects;
DROP POLICY IF EXISTS "porttohub_storage_operadores_delete" ON storage.objects;

CREATE POLICY "porttohub_storage_select"
  ON storage.objects FOR SELECT TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'condominios'
    AND (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

CREATE POLICY "porttohub_storage_insert"
  ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'condominios'
    AND (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

CREATE POLICY "porttohub_storage_update"
  ON storage.objects FOR UPDATE TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'condominios'
    AND (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  )
  WITH CHECK (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'condominios'
    AND (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

CREATE POLICY "porttohub_storage_delete"
  ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'condominios'
    AND (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

CREATE POLICY "porttohub_storage_operadores_select"
  ON storage.objects FOR SELECT TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'operadores'
    AND (
      (storage.foldername(name))[2] = auth.uid()::text
      OR public.operador_tem_acesso_global()
    )
  );

CREATE POLICY "porttohub_storage_operadores_insert"
  ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

CREATE POLICY "porttohub_storage_operadores_update"
  ON storage.objects FOR UPDATE TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  )
  WITH CHECK (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

CREATE POLICY "porttohub_storage_operadores_delete"
  ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

-- ============================================================================
-- 6. VALIDAÇÃO SEGURA DA CONSTRAINT chk_passes_qr_usos_limite (SEM APAGAR DADOS)
-- ============================================================================
DO $$
DECLARE
  v_violacoes INTEGER := 0;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_passes_qr_usos_limite') THEN
    ALTER TABLE public.passes_virtuais_qr
      ADD CONSTRAINT chk_passes_qr_usos_limite
      CHECK (
        COALESCE(usos_realizados, 0) >= 0
        AND COALESCE(max_usos, limite_usos, 1) >= 1
        AND COALESCE(usos_realizados, 0) <= COALESCE(max_usos, limite_usos, 1)
      ) NOT VALID;
  END IF;

  SELECT COUNT(*)
  INTO v_violacoes
  FROM public.passes_virtuais_qr
  WHERE NOT (
    COALESCE(usos_realizados, 0) >= 0
    AND COALESCE(max_usos, limite_usos, 1) >= 1
    AND COALESCE(usos_realizados, 0) <= COALESCE(max_usos, limite_usos, 1)
  );

  IF v_violacoes = 0 THEN
    ALTER TABLE public.passes_virtuais_qr
      VALIDATE CONSTRAINT chk_passes_qr_usos_limite;
  ELSE
    RAISE NOTICE 'Aviso: % registro(s) existente(s) violam chk_passes_qr_usos_limite; constraint mantida NOT VALID para nao apagar nem alterar historico.', v_violacoes;
  END IF;
END $$;

COMMIT;

NOTIFY pgrst, 'reload schema';
