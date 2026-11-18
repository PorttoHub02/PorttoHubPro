-- ============================================================================
-- PORTTOHUB PRO — 09_VALIDACAO_SEGURANCA.sql (100% SOMENTE LEITURA)
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   Audita o banco de DESTINO após a aplicação dos scripts 02 a 08 para provar
--   que não restou nenhuma política permissiva USING (true), nenhum bucket
--   público indevido, nenhum acesso anônimo aberto e nenhum operador sem vínculo.
--
-- ONDE EXECUTAR:
--   Supabase Dashboard do DESTINO -> SQL Editor -> New query -> Run.
-- ============================================================================

-- 1. GARANTE QUE NAO EXISTA NENHUMA POLITICA USING (true) / WITH CHECK (true)
SELECT
  schemaname,
  tablename,
  policyname,
  cmd,
  qual,
  with_check
FROM pg_policies
WHERE schemaname IN ('public', 'storage')
  AND (
    COALESCE(qual, '') IN ('true', '(true)')
    OR COALESCE(with_check, '') IN ('true', '(true)')
  )
ORDER BY schemaname, tablename;

-- 2. GARANTE QUE TODAS AS TABELAS PUBLIC ESTAO COM RLS ATIVO
SELECT
  c.relname AS tabela,
  c.relrowsecurity AS rls_ativo
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
  AND c.relrowsecurity = FALSE
ORDER BY c.relname;

-- 3. GARANTE QUE O ROLE anon NAO POSSUI MAIS SELECT/INSERT/UPDATE/DELETE INDEVIDO
SELECT
  table_name,
  grantee,
  privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND grantee = 'anon'
ORDER BY table_name, privilege_type;

-- 4. CONFERE QUE O BUCKET 'encomendas' ESTA PRIVADO (bucket_publico = false)
SELECT id, name, public AS bucket_publico, file_size_limit
FROM storage.buckets
WHERE id = 'encomendas';

-- 5. CONFERE QUEM POSSUI acesso_global_condominios = TRUE
SELECT id, nome, login, email, nivel_acesso, perfil, acesso_global_condominios, ativo
FROM public.operadores
WHERE acesso_global_condominios = TRUE;

-- 6. CONFERE OPERADORES AINDA SEM auth_user_id (devem ser 0 antes do go-live final)
SELECT id, nome, login, email, condominio_id, ativo
FROM public.operadores
WHERE auth_user_id IS NULL AND COALESCE(ativo, TRUE) = TRUE;

-- 7. RESUMO CONSOLIDADO PARA CONFERENCIA RAPIDA NO SQL EDITOR
SELECT * FROM (
  SELECT
    1 AS ordem,
    '1. Politicas permissivas (USING true)' AS verificacao,
    (
      SELECT COUNT(*) FROM pg_policies
      WHERE schemaname IN ('public', 'storage')
        AND (COALESCE(qual, '') IN ('true', '(true)') OR COALESCE(with_check, '') IN ('true', '(true)'))
    ) AS valor_encontrado,
    'Esperado: 0' AS criterio,
    CASE WHEN (
      SELECT COUNT(*) FROM pg_policies
      WHERE schemaname IN ('public', 'storage')
        AND (COALESCE(qual, '') IN ('true', '(true)') OR COALESCE(with_check, '') IN ('true', '(true)'))
    ) = 0 THEN 'OK' ELSE 'ATENCAO' END AS status
  UNION ALL
  SELECT
    2,
    '2. Tabelas public sem RLS ativo',
    (
      SELECT COUNT(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity = FALSE
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity = FALSE
    ) = 0 THEN 'OK' ELSE 'ATENCAO' END
  UNION ALL
  SELECT
    3,
    '3. Permissoes diretas para anon em public',
    (
      SELECT COUNT(*) FROM information_schema.role_table_grants
      WHERE table_schema = 'public' AND grantee = 'anon'
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM information_schema.role_table_grants
      WHERE table_schema = 'public' AND grantee = 'anon'
    ) = 0 THEN 'OK' ELSE 'ATENCAO' END
  UNION ALL
  SELECT
    4,
    '4. Bucket encomendas configurado como privado',
    (
      SELECT COUNT(*) FROM storage.buckets
      WHERE id = 'encomendas' AND public = FALSE
    ),
    'Esperado: 1',
    CASE WHEN (
      SELECT COUNT(*) FROM storage.buckets
      WHERE id = 'encomendas' AND public = FALSE
    ) = 1 THEN 'OK' ELSE 'ATENCAO' END
  UNION ALL
  SELECT
    5,
    '5. Administradores globais ativos vinculados ao Auth',
    (
      SELECT COUNT(*) FROM public.operadores
      WHERE acesso_global_condominios = TRUE
        AND COALESCE(ativo, TRUE) = TRUE
        AND auth_user_id IS NOT NULL
    ),
    'Esperado: >= 1',
    CASE WHEN (
      SELECT COUNT(*) FROM public.operadores
      WHERE acesso_global_condominios = TRUE
        AND COALESCE(ativo, TRUE) = TRUE
        AND auth_user_id IS NOT NULL
    ) >= 1 THEN 'OK' ELSE 'ATENCAO' END
  UNION ALL
  SELECT
    6,
    '6. Operadores ativos ainda sem auth_user_id',
    (
      SELECT COUNT(*) FROM public.operadores
      WHERE auth_user_id IS NULL AND COALESCE(ativo, TRUE) = TRUE
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM public.operadores
      WHERE auth_user_id IS NULL AND COALESCE(ativo, TRUE) = TRUE
    ) = 0 THEN 'OK' ELSE 'ATENCAO' END
) resumo
ORDER BY ordem;

-- 8. CONFERE PERFIS PADRONIZADOS E ASSINATURAS DE FUNCOES OFICIAIS
SELECT
  COALESCE(NULLIF(trim(perfil), ''), '(vazio)') AS perfil,
  COUNT(*) AS total,
  COUNT(*) FILTER (WHERE COALESCE(acesso_global_condominios, FALSE) = TRUE) AS com_acesso_global
FROM public.operadores
GROUP BY 1
ORDER BY 1;

SELECT
  p.proname AS funcao,
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
    'operador_pode_editar_alvo_local',
    'proteger_campos_operador',
    'validar_e_consumir_passe_qr'
  )
ORDER BY p.proname, argumentos;

SELECT
  tgname AS trigger_nome,
  tgenabled AS status
FROM pg_trigger t
JOIN pg_class c ON c.oid = t.tgrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname = 'operadores'
  AND NOT t.tgisinternal;
