-- ============================================================================
-- PORTTOHUB PRO — 05_FUNCOES_AUTORIZACAO.sql
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   Cria funções PostgreSQL seguras (SECURITY DEFINER + search_path fixo) usadas
--   pelas políticas de RLS e pelo Storage para verificar:
--     1. Quem é o operador autenticado (`operador_atual_id`).
--     2. Se possui acesso global explícito (`operador_tem_acesso_global`).
--     3. Se pode gerenciar operadores globalmente (`operador_pode_gerenciar_operadores()` — SEM parâmetro, EXCLUSIVA do acesso global).
--     4. Se pode gerenciar operadores localmente (`operador_pode_gerenciar_operadores(TEXT)` — COM p_condominio_id, admin_geral ou admin_condominio do próprio condomínio principal).
--     5. Se pode acessar dados de um condomínio (`operador_pode_acessar_condominio`).
--     6. Guardas de imutabilidade de perfil próprio e proibição de transferência entre condomínios por admin_condominio.
--
-- REGRAS OFICIAIS DE SEGURANCA:
--   - Perfis padronizados: admin_geral, admin_condominio, supervisor, operador.
--   - Nunca utiliza nivel_acesso isoladamente para conceder privilégios globais ou administrativos.
--   - SUPERVISOR não recebe poderes administrativos de gestão de operadores automaticamente.
--   - ADMIN_CONDOMINIO gerencia somente operadores do seu próprio condomínio principal,
--     não concede acesso global, não cria admin_geral, não altera o próprio perfil/privilégios/vínculo
--     e não transfere operadores entre condomínios.
--
-- ONDE EXECUTAR:
--   Supabase Dashboard do DESTINO -> SQL Editor -> New query -> Run.
-- ============================================================================

BEGIN;

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

-- SEM parâmetro: EXCLUSIVA de acesso global (admin_geral com acesso_global_condominios = TRUE)
CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT public.operador_tem_acesso_global();
$$;

-- COM parâmetro p_condominio_id: administração global OU admin_condominio do próprio condomínio principal.
-- Supervisor e operador NÃO recebem permissão administrativa.
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
            lower(COALESCE(o.perfil, '')) = 'admin_condominio'
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

-- Impede que operadores não globais (inclusive admin_condominio) alterem próprio perfil, privilégios ou vínculo condominial
CREATE OR REPLACE FUNCTION public.operador_preserva_proprio_perfil(
  p_id UUID,
  p_perfil TEXT,
  p_nivel INTEGER,
  p_custom_id TEXT,
  p_global BOOLEAN,
  p_condominio_id UUID,
  p_ativo BOOLEAN,
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
      AND lower(COALESCE(cur.perfil, '')) IS NOT DISTINCT FROM lower(COALESCE(p_perfil, ''))
      AND cur.nivel_acesso IS NOT DISTINCT FROM p_nivel
      AND cur.nivel_acesso_custom_id IS NOT DISTINCT FROM p_custom_id
      AND COALESCE(cur.acesso_global_condominios, FALSE) = COALESCE(p_global, FALSE)
      AND cur.condominio_id IS NOT DISTINCT FROM p_condominio_id
      AND COALESCE(cur.ativo, TRUE) = COALESCE(p_ativo, TRUE)
      AND cur.auth_user_id IS NOT DISTINCT FROM p_auth_user_id
  );
$$;

-- Garante que admin_condominio só edite operadores subordinados do mesmo condomínio (sem transferir nem tocar admin_geral/si mesmo)
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
    AND lower(COALESCE(p_novo_perfil, 'operador')) IN ('admin_condominio', 'supervisor', 'operador')
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

-- Revoga execução pública irrestrita e libera apenas para authenticated / service_role
REVOKE ALL ON FUNCTION public.operador_atual_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.operador_tem_acesso_global() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.operador_pode_gerenciar_operadores() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.operador_pode_gerenciar_operadores(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.operador_pode_gerenciar_operadores(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.operador_pode_acessar_condominio(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.operador_pode_acessar_condominio(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.operador_preserva_proprio_perfil(UUID, TEXT, INTEGER, TEXT, BOOLEAN, UUID, BOOLEAN, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.operador_pode_editar_alvo_local(UUID, UUID, TEXT, INTEGER, BOOLEAN) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.operador_atual_id() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_tem_acesso_global() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_gerenciar_operadores() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_gerenciar_operadores(TEXT) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_gerenciar_operadores(UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_acessar_condominio(TEXT) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_acessar_condominio(UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_preserva_proprio_perfil(UUID, TEXT, INTEGER, TEXT, BOOLEAN, UUID, BOOLEAN, UUID) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.operador_pode_editar_alvo_local(UUID, UUID, TEXT, INTEGER, BOOLEAN) TO authenticated, service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';

-- Conferência das funções oficiais aplicadas
SELECT
  p.proname AS nome_funcao,
  pg_get_function_identity_arguments(p.oid) AS argumentos
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.proname IN (
    'operador_atual_id',
    'operador_tem_acesso_global',
    'operador_pode_gerenciar_operadores',
    'operador_pode_acessar_condominio',
    'operador_preserva_proprio_perfil',
    'operador_pode_editar_alvo_local'
  )
ORDER BY p.proname, argumentos;
