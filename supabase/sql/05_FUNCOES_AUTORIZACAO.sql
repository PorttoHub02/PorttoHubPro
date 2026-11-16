
-- ============================================================================
-- PORTTOHUB PRO — 05_FUNCOES_AUTORIZACAO.sql
-- VERSAO CORRIGIDA — ADMINISTRACAO POR CONDOMINIO
-- ============================================================================
--
-- PERFIS OFICIAIS:
--   admin_geral       = acesso global
--   admin_condominio  = administracao do proprio condominio
--   supervisor        = sem poder administrativo automatico
--   operador          = sem poder administrativo
--
-- REGRA DE SEGURANCA:
--   O acesso global depende exclusivamente de
--   acesso_global_condominios = TRUE.
--
--   O administrador de condominio somente pode gerenciar
--   operadores vinculados ao condominio autorizado.
--
--   A funcao sem parametro e exclusiva do acesso global.
--   As politicas RLS devem usar a funcao com condominio_id
--   para autorizar administracao local.
--
-- EXECUTAR NO SUPABASE DO DESTINO.
-- ============================================================================

BEGIN;

-- 1. IDENTIFICAR O OPERADOR AUTENTICADO
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


-- 2. VERIFICAR ACESSO GLOBAL
CREATE OR REPLACE FUNCTION public.operador_tem_acesso_global()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.operadores o
    WHERE o.auth_user_id = auth.uid()
      AND COALESCE(o.ativo, TRUE) = TRUE
      AND COALESCE(o.acesso_global_condominios, FALSE) = TRUE
  );
$$;


-- 3. GERENCIAMENTO GLOBAL DE OPERADORES
-- IMPORTANTE:
-- Sem parametro, somente Administrador Geral com
-- acesso_global_condominios = TRUE recebe autorizacao.
--
-- Isso protege politicas antigas que utilizem a funcao
-- sem informar o condominio.

CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT public.operador_tem_acesso_global();
$$;


-- 4. GERENCIAMENTO DE OPERADORES POR CONDOMINIO
-- Administrador Geral pode gerenciar qualquer condominio.
-- Administrador local somente pode gerenciar condominios
-- aos quais possui vinculo ativo.

CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores(
  p_condominio_id TEXT
)
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
    AND lower(trim(p_condominio_id)) NOT IN ('todos', 'global')
    AND EXISTS (
      SELECT 1
      FROM public.operadores o
      WHERE o.auth_user_id = auth.uid()
        AND COALESCE(o.ativo, TRUE) = TRUE
        AND (
          COALESCE(o.acesso_global_condominios, FALSE) = TRUE

          OR (
            lower(trim(COALESCE(o.perfil, ''))) = 'admin_condominio'
            AND (
              o.condominio_id::text = trim(p_condominio_id)

              OR EXISTS (
                SELECT 1
                FROM public.operador_condominios oc
                WHERE oc.operador_id = o.id
                  AND oc.condominio_id::text = trim(p_condominio_id)
                  AND COALESCE(oc.ativo, TRUE) = TRUE
              )
            )
          )
        )
    );
$$;


-- 5. VERSAO UUID DA FUNCAO DE GERENCIAMENTO

CREATE OR REPLACE FUNCTION public.operador_pode_gerenciar_operadores(
  p_condominio_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT public.operador_pode_gerenciar_operadores(
    p_condominio_id::text
  );
$$;


-- 6. VERIFICAR ACESSO A UM CONDOMINIO
CREATE OR REPLACE FUNCTION public.operador_pode_acessar_condominio(
  p_condominio_id TEXT
)
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
    AND lower(trim(p_condominio_id)) NOT IN ('todos', 'global')
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
              AND oc.condominio_id::text = trim(p_condominio_id)
              AND COALESCE(oc.ativo, TRUE) = TRUE
          )
        )
    );
$$;


-- 7. VERSAO UUID DA FUNCAO DE ACESSO

CREATE OR REPLACE FUNCTION public.operador_pode_acessar_condominio(
  p_condominio_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT public.operador_pode_acessar_condominio(
    p_condominio_id::text
  );
$$;


-- 8. REVOGAR EXECUCAO PUBLICA

REVOKE ALL ON FUNCTION public.operador_atual_id()
FROM PUBLIC;

REVOKE ALL ON FUNCTION public.operador_tem_acesso_global()
FROM PUBLIC;

REVOKE ALL ON FUNCTION public.operador_pode_gerenciar_operadores()
FROM PUBLIC;

REVOKE ALL ON FUNCTION public.operador_pode_gerenciar_operadores(TEXT)
FROM PUBLIC;

REVOKE ALL ON FUNCTION public.operador_pode_gerenciar_operadores(UUID)
FROM PUBLIC;

REVOKE ALL ON FUNCTION public.operador_pode_acessar_condominio(TEXT)
FROM PUBLIC;

REVOKE ALL ON FUNCTION public.operador_pode_acessar_condominio(UUID)
FROM PUBLIC;


-- 9. LIBERAR EXECUCAO SOMENTE AOS PERFIS AUTENTICADOS
-- E AO SERVICE ROLE.

GRANT EXECUTE ON FUNCTION public.operador_atual_id()
TO authenticated, service_role;

GRANT EXECUTE ON FUNCTION public.operador_tem_acesso_global()
TO authenticated, service_role;

GRANT EXECUTE ON FUNCTION public.operador_pode_gerenciar_operadores()
TO authenticated, service_role;

GRANT EXECUTE ON FUNCTION public.operador_pode_gerenciar_operadores(TEXT)
TO authenticated, service_role;

GRANT EXECUTE ON FUNCTION public.operador_pode_gerenciar_operadores(UUID)
TO authenticated, service_role;

GRANT EXECUTE ON FUNCTION public.operador_pode_acessar_condominio(TEXT)
TO authenticated, service_role;

GRANT EXECUTE ON FUNCTION public.operador_pode_acessar_condominio(UUID)
TO authenticated, service_role;


COMMIT;

-- 10. ATUALIZAR ESQUEMA DO POSTGREST

NOTIFY pgrst, 'reload schema';


-- 11. CONFERENCIA DAS FUNCOES CRIADAS

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
    'operador_pode_acessar_condominio'
  )
ORDER BY p.proname, argumentos;
