-- ============================================================================
-- PORTTOHUB PRO — 09_VALIDACAO_SEGURANCA.sql (100% SOMENTE LEITURA)
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   Audita o banco de DESTINO após a aplicação dos scripts 02 a 08 e/ou 11
--   para comprovar RLS ativa, ausência de USING (true), revogação de anon/PUBLIC
--   em tabelas e funções SECURITY DEFINER/RPC, trigger INVOKER, Storage
--   privado com 8 políticas e constraint chk_passes_qr_usos_limite validada.
--
-- ONDE EXECUTAR:
--   Supabase Dashboard do DESTINO -> SQL Editor -> New query -> Run.
-- ============================================================================

-- 1. POLITICAS PERMISSIVAS USING (true) / WITH CHECK (true) (Esperado: 0 linhas)
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

-- 2. TABELAS PUBLIC SEM RLS ATIVO OU SEM POLITICA (Esperado: 0 linhas)
SELECT
  c.relname AS tabela,
  c.relrowsecurity AS rls_ativo,
  (SELECT COUNT(*) FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = c.relname) AS qtd_politicas
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
  AND (
    c.relrowsecurity = FALSE
    OR NOT EXISTS (
      SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = c.relname
    )
  )
ORDER BY c.relname;

-- 3. PRIVILEGIOS INDEVIDOS EM TABELAS PUBLIC (anon, PUBLIC ou TRUNCATE/TRIGGER/REFERENCES em authenticated)
SELECT
  table_name,
  grantee,
  privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND (
    grantee IN ('anon', 'PUBLIC')
    OR (grantee = 'authenticated' AND privilege_type IN ('TRUNCATE', 'TRIGGER', 'REFERENCES'))
  )
ORDER BY table_name, grantee, privilege_type;

-- 4. PRIVILEGIOS EXECUTE INDEVIDOS EM FUNCOES DE SEGURANCA/RPC (anon ou public nao devem executar)
SELECT
  p.proname AS funcao,
  pg_get_function_identity_arguments(p.oid) AS argumentos,
  p.prosecdef AS is_security_definer,
  has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_executa,
  has_function_privilege('public', p.oid, 'EXECUTE') AS public_executa,
  has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authenticated_executa
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.proname IN (
    'operador_atual_id',
    'operador_tem_acesso_global',
    'operador_pode_gerenciar_operadores',
    'operador_pode_acessar_condominio',
    'operador_auth_email_corresponde',
    'operador_tem_permissao_modulo',
    'operador_preserva_proprio_perfil',
    'operador_pode_editar_alvo_local',
    'proteger_campos_operador',
    'proteger_campos_passe_qr',
    'validar_e_consumir_passe_qr'
  )
ORDER BY p.proname, argumentos;

-- 5. BUCKET 'encomendas' E POLITICAS PRIVADAS DE STORAGE
SELECT id, name, public AS bucket_publico, file_size_limit, allowed_mime_types
FROM storage.buckets
WHERE id = 'encomendas';

SELECT policyname, cmd, roles
FROM pg_policies
WHERE schemaname = 'storage'
  AND tablename = 'objects'
ORDER BY policyname;

-- 6. CONFERENCIA DA CONSTRAINT chk_passes_qr_usos_limite
SELECT conname, convalidated
FROM pg_constraint
WHERE conname = 'chk_passes_qr_usos_limite';

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
    ) = 0 THEN 'OK' ELSE 'FALHA' END AS status
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
    ) = 0 THEN 'OK' ELSE 'FALHA' END
  UNION ALL
  SELECT
    3,
    '3. Tabelas public sem nenhuma politica RLS',
    (
      SELECT COUNT(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
        AND NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = c.relname)
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
        AND NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = c.relname)
    ) = 0 THEN 'OK' ELSE 'FALHA' END
  UNION ALL
  SELECT
    4,
    '4. Grants diretos anon/PUBLIC ou excessivos (TRUNCATE/TRIGGER/REFERENCES) em public',
    (
      SELECT COUNT(*) FROM information_schema.role_table_grants
      WHERE table_schema = 'public'
        AND (
          grantee IN ('anon', 'PUBLIC')
          OR (grantee = 'authenticated' AND privilege_type IN ('TRUNCATE', 'TRIGGER', 'REFERENCES'))
        )
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM information_schema.role_table_grants
      WHERE table_schema = 'public'
        AND (
          grantee IN ('anon', 'PUBLIC')
          OR (grantee = 'authenticated' AND privilege_type IN ('TRUNCATE', 'TRIGGER', 'REFERENCES'))
        )
    ) = 0 THEN 'OK' ELSE 'FALHA' END
  UNION ALL
  SELECT
    5,
    '5. Funcoes de seguranca/RPC executaveis por anon ou PUBLIC',
    (
      SELECT COUNT(*) FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname IN (
          'operador_atual_id', 'operador_tem_acesso_global', 'operador_pode_gerenciar_operadores',
          'operador_pode_acessar_condominio', 'operador_auth_email_corresponde',
          'operador_tem_permissao_modulo', 'operador_preserva_proprio_perfil',
          'operador_pode_editar_alvo_local', 'proteger_campos_operador',
          'proteger_campos_passe_qr', 'validar_e_consumir_passe_qr'
        )
        AND (
          has_function_privilege('anon', p.oid, 'EXECUTE')
          OR has_function_privilege('public', p.oid, 'EXECUTE')
        )
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname IN (
          'operador_atual_id', 'operador_tem_acesso_global', 'operador_pode_gerenciar_operadores',
          'operador_pode_acessar_condominio', 'operador_auth_email_corresponde',
          'operador_tem_permissao_modulo', 'operador_preserva_proprio_perfil',
          'operador_pode_editar_alvo_local', 'proteger_campos_operador',
          'proteger_campos_passe_qr', 'validar_e_consumir_passe_qr'
        )
        AND (
          has_function_privilege('anon', p.oid, 'EXECUTE')
          OR has_function_privilege('public', p.oid, 'EXECUTE')
        )
    ) = 0 THEN 'OK' ELSE 'FALHA' END
  UNION ALL
  SELECT
    6,
    '6. Trigger proteger_campos_operador em modo SECURITY INVOKER',
    (
      SELECT COUNT(*) FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.proname = 'proteger_campos_operador' AND p.prosecdef = FALSE
    ),
    'Esperado: 1',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.proname = 'proteger_campos_operador' AND p.prosecdef = FALSE
    ) = 1 THEN 'OK' ELSE 'FALHA' END
  UNION ALL
  SELECT
    7,
    '7. Bucket encomendas privado + 8 politicas (condominios + operadores)',
    (
      SELECT CASE WHEN
        (SELECT COUNT(*) FROM storage.buckets WHERE id = 'encomendas' AND public = FALSE) = 1
        AND (
          SELECT COUNT(*) FROM pg_policies
          WHERE schemaname = 'storage' AND tablename = 'objects'
            AND policyname IN (
              'porttohub_storage_select', 'porttohub_storage_insert',
              'porttohub_storage_update', 'porttohub_storage_delete',
              'porttohub_storage_operadores_select', 'porttohub_storage_operadores_insert',
              'porttohub_storage_operadores_update', 'porttohub_storage_operadores_delete'
            )
        ) = 8
      THEN 1 ELSE 0 END
    ),
    'Esperado: 1',
    CASE WHEN
      (SELECT COUNT(*) FROM storage.buckets WHERE id = 'encomendas' AND public = FALSE) = 1
      AND (
        SELECT COUNT(*) FROM pg_policies
        WHERE schemaname = 'storage' AND tablename = 'objects'
          AND policyname IN (
            'porttohub_storage_select', 'porttohub_storage_insert',
            'porttohub_storage_update', 'porttohub_storage_delete',
            'porttohub_storage_operadores_select', 'porttohub_storage_operadores_insert',
            'porttohub_storage_operadores_update', 'porttohub_storage_operadores_delete'
          )
      ) = 8
    THEN 'OK' ELSE 'ATENCAO' END
  UNION ALL
  SELECT
    8,
    '8. Constraint chk_passes_qr_usos_limite validada (convalidated)',
    (
      SELECT COUNT(*) FROM pg_constraint
      WHERE conname = 'chk_passes_qr_usos_limite' AND convalidated = TRUE
    ),
    'Esperado: 1',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_constraint
      WHERE conname = 'chk_passes_qr_usos_limite' AND convalidated = TRUE
    ) = 1 THEN 'OK' ELSE 'ATENCAO' END
  UNION ALL
  SELECT
    9,
    '9. Administradores globais ativos vinculados ao Auth',
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
    ) >= 1 THEN 'OK' ELSE 'FALHA' END
  UNION ALL
  SELECT
    10,
    '10. Operadores ativos ainda sem auth_user_id',
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
