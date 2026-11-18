-- ============================================================================
-- PORTTOHUB PRO — 12_AUDITORIA_FINAL_SEGURANCA.sql (100% SOMENTE LEITURA)
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   Auditoria completa, objetiva e não destrutiva do banco Supabase após a
--   aplicação do script 11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql (ou instalação
--   completa 01–08). Inspeciona definições reais (pg_get_functiondef), gatilhos,
--   privilégios (has_function_privilege), políticas granulares e FKs cruzadas.
-- ============================================================================

-- A. DIAGNÓSTICO DE POLÍTICAS PERMISSIVAS OU INCOMPLETAS (Esperado: 0 linhas)
SELECT
  schemaname,
  tablename,
  policyname,
  cmd,
  roles,
  qual,
  with_check
FROM pg_policies
WHERE schemaname IN ('public', 'storage')
  AND (
    COALESCE(qual, '') IN ('true', '(true)')
    OR COALESCE(with_check, '') IN ('true', '(true)')
    OR (schemaname = 'storage' AND roles::text ILIKE '%public%')
  )
ORDER BY schemaname, tablename, policyname;

-- B. DIAGNÓSTICO DE MODO E PRIVILÉGIOS DE TODAS AS FUNÇÕES CRÍTICAS
SELECT
  p.proname AS funcao,
  pg_get_function_identity_arguments(p.oid) AS argumentos,
  CASE WHEN p.prosecdef THEN 'SECURITY DEFINER' ELSE 'SECURITY INVOKER' END AS modo_execucao,
  has_function_privilege('public', p.oid, 'EXECUTE') AS public_executa,
  has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_executa,
  has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authenticated_executa,
  has_function_privilege('service_role', p.oid, 'EXECUTE') AS service_role_executa
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

-- C. INVENTÁRIO POR TABELA DAS 35 TABELAS CANÔNICAS E POLITICAS APLICADAS
SELECT
  c.relname AS tabela,
  c.relrowsecurity AS rls_ativo,
  COUNT(p.policyname) AS qtd_politicas,
  COUNT(p.policyname) FILTER (WHERE p.cmd = 'ALL') AS qtd_for_all,
  BOOL_OR(
    COALESCE(p.qual, '') ILIKE '%operador_tem_permissao_modulo%'
    OR COALESCE(p.with_check, '') ILIKE '%operador_tem_permissao_modulo%'
  ) AS usa_permissao_modulo
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_policies p ON p.schemaname = 'public' AND p.tablename = c.relname
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
GROUP BY c.relname, c.relrowsecurity
ORDER BY c.relname;

-- D. QUADRO CONSOLIDADO DA AUDITORIA FINAL DE SEGURANÇA (18 VERIFICAÇÕES)
WITH checks AS (
  SELECT
    1 AS ordem,
    '1. Trigger proteger_campos_operador em SECURITY INVOKER + habilitada'::text AS verificacao,
    (
      SELECT CASE WHEN
        EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public' AND p.proname = 'proteger_campos_operador' AND p.prosecdef = FALSE
        )
        AND EXISTS (
          SELECT 1 FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relname = 'operadores'
            AND t.tgname = 'trg_proteger_campos_operador'
            AND t.tgenabled IN ('O', 'A')
        )
      THEN 1 ELSE 0 END
    )::bigint AS valor_encontrado,
    'Esperado: 1 (INVOKER + ativa)'::text AS criterio,
    CASE WHEN
      EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname = 'proteger_campos_operador' AND p.prosecdef = FALSE
      )
      AND EXISTS (
        SELECT 1 FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'operadores'
          AND t.tgname = 'trg_proteger_campos_operador'
          AND t.tgenabled IN ('O', 'A')
      )
    THEN 'OK' ELSE 'FALHA' END AS status,
    'Impede auto-bypass via current_user=postgres na tabela operadores.'::text AS explicacao

  UNION ALL
  SELECT
    2,
    '2. Coluna JSONB permissoes + perfil + vinculo protegidos na auto-edicao',
    (
      SELECT CASE WHEN
        EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'operador_preserva_proprio_perfil'
            AND pg_get_functiondef(p.oid) ILIKE '%permissoes%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'proteger_campos_operador'
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.permissoes%'
            AND pg_get_functiondef(p.oid) ILIKE '%OLD.condominio_id%'
            AND pg_get_functiondef(p.oid) ILIKE '%OLD.ativo%'
        )
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN
      EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'operador_preserva_proprio_perfil'
          AND pg_get_functiondef(p.oid) ILIKE '%permissoes%'
      )
      AND EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'proteger_campos_operador'
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.permissoes%'
          AND pg_get_functiondef(p.oid) ILIKE '%OLD.condominio_id%'
          AND pg_get_functiondef(p.oid) ILIKE '%OLD.ativo%'
      )
    THEN 'OK' ELSE 'FALHA' END,
    'Bloqueia auto-alteracao de permissoes, transferencia local de condominio e edicao por conta inativa.'

  UNION ALL
  SELECT
    3,
    '3. Trigger proteger_campos_passe_qr (SECURITY INVOKER + ativa) protege usos/status/token',
    (
      SELECT CASE WHEN
        EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'proteger_campos_passe_qr'
            AND p.prosecdef = FALSE
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.usos_realizados%'
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.max_usos%'
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.limite_usos%'
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.status%'
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.token%'
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.condominio_id%'
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.data_validade%'
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.hora_inicio%'
            AND pg_get_functiondef(p.oid) ILIKE '%NEW.hora_fim%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relname = 'passes_virtuais_qr'
            AND t.tgname = 'trg_proteger_campos_passe_qr'
            AND t.tgenabled IN ('O', 'A')
        )
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN
      EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'proteger_campos_passe_qr'
          AND p.prosecdef = FALSE
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.usos_realizados%'
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.max_usos%'
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.limite_usos%'
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.status%'
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.token%'
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.condominio_id%'
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.data_validade%'
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.hora_inicio%'
          AND pg_get_functiondef(p.oid) ILIKE '%NEW.hora_fim%'
      )
      AND EXISTS (
        SELECT 1 FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'passes_virtuais_qr'
          AND t.tgname = 'trg_proteger_campos_passe_qr'
          AND t.tgenabled IN ('O', 'A')
      )
    THEN 'OK' ELSE 'FALHA' END,
    'Bloqueia adulteracao direta de usos_realizados, max_usos, status, token e janelas fora da RPC oficial.'

  UNION ALL
  SELECT
    4,
    '4. Todas as funcoes criticas/triggers/RPC sem EXECUTE para anon ou PUBLIC',
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
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Verifica revogacao real de EXECUTE para PUBLIC e anon incluindo operador_tem_permissao_modulo e proteger_campos_passe_qr.'

  UNION ALL
  SELECT
    5,
    '5. RPC validar_e_consumir_passe_qr sem bypass current_user + service_role/modulo/FOR UPDATE',
    (
      SELECT CASE WHEN
        EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'validar_e_consumir_passe_qr'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%current_user NOT IN%'
            AND pg_get_functiondef(p.oid) ILIKE '%service_role%'
            AND pg_get_functiondef(p.oid) ILIKE '%operador_tem_permissao_modulo%'
            AND pg_get_functiondef(p.oid) ILIKE '%o.auth_user_id = auth.uid()%'
            AND pg_get_functiondef(p.oid) ILIKE '%FOR UPDATE%'
            AND pg_get_functiondef(p.oid) ILIKE '%porttohub.rpc_passe_qr_consumo%'
        )
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN EXISTS (
      SELECT 1 FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname = 'validar_e_consumir_passe_qr'
        AND pg_get_functiondef(p.oid) NOT ILIKE '%current_user NOT IN%'
        AND pg_get_functiondef(p.oid) ILIKE '%service_role%'
        AND pg_get_functiondef(p.oid) ILIKE '%operador_tem_permissao_modulo%'
        AND pg_get_functiondef(p.oid) ILIKE '%o.auth_user_id = auth.uid()%'
        AND pg_get_functiondef(p.oid) ILIKE '%FOR UPDATE%'
        AND pg_get_functiondef(p.oid) ILIKE '%porttohub.rpc_passe_qr_consumo%'
    ) THEN 'OK' ELSE 'FALHA' END,
    'Confirma eliminacao do bypass por current_user, exigencia estrita de service_role/auth.uid(), permissao do modulo e lock FOR UPDATE.'

  UNION ALL
  SELECT
    6,
    '6. Auxiliar operador_auth_email_corresponde bloqueia consulta de terceiros por usuarios comuns',
    (
      SELECT CASE WHEN
        EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'operador_auth_email_corresponde'
            AND pg_get_functiondef(p.oid) ILIKE '%p_auth_user_id IS DISTINCT FROM auth.uid()%'
            AND pg_get_functiondef(p.oid) ILIKE '%service_role%'
            AND pg_get_functiondef(p.oid) ILIKE '%session_user%'
        )
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN EXISTS (
      SELECT 1 FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname = 'operador_auth_email_corresponde'
        AND pg_get_functiondef(p.oid) ILIKE '%p_auth_user_id IS DISTINCT FROM auth.uid()%'
        AND pg_get_functiondef(p.oid) ILIKE '%service_role%'
        AND pg_get_functiondef(p.oid) ILIKE '%session_user%'
    ) THEN 'OK' ELSE 'FALHA' END,
    'Restringe leitura em auth.users ao proprio auth.uid(), service_role ou sessao SQL administrativa direta.'

  UNION ALL
  SELECT
    7,
    '7. Politicas permissivas USING (true) / WITH CHECK (true)',
    (
      SELECT COUNT(*) FROM pg_policies
      WHERE schemaname IN ('public', 'storage')
        AND (COALESCE(qual, '') IN ('true', '(true)') OR COALESCE(with_check, '') IN ('true', '(true)'))
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_policies
      WHERE schemaname IN ('public', 'storage')
        AND (COALESCE(qual, '') IN ('true', '(true)') OR COALESCE(with_check, '') IN ('true', '(true)'))
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Nenhuma politica permissiva irrestrita pode existir em public ou storage.'

  UNION ALL
  SELECT
    8,
    '8. Tabelas public sem RLS ativo',
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
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Todas as tabelas do schema public devem permanecer com RLS habilitado.'

  UNION ALL
  SELECT
    9,
    '9. Tabelas public sem nenhuma politica RLS',
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
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Nenhuma tabela em public pode ficar sem politicas RLS explicitas.'

  UNION ALL
  SELECT
    10,
    '10. Grants indevidos (anon/PUBLIC) ou excessivos (TRUNCATE/TRIGGER/REFERENCES)',
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
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'authenticated possui apenas SELECT/INSERT/UPDATE/DELETE; anon e PUBLIC tem 0 privilegios.'

  UNION ALL
  SELECT
    11,
    '11. Politicas RLS granulares (zero FOR ALL em public)',
    (
      SELECT COUNT(*) FROM pg_policies
      WHERE schemaname = 'public' AND cmd = 'ALL'
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_policies
      WHERE schemaname = 'public' AND cmd = 'ALL'
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Cada tabela possui politicas separadas para SELECT, INSERT, UPDATE e DELETE.'

  UNION ALL
  SELECT
    12,
    '12. Politicas operacionais em public utilizam operador_tem_permissao_modulo nas tabelas de modulos',
    (
      SELECT COUNT(*) FROM pg_policies
      WHERE schemaname = 'public'
        AND tablename IN (
          'moradores', 'encomendas_itens', 'lotes_re', 'entregadores',
          'custodia', 'chaves', 'movimentacao_chaves', 'prestadores', 'prestadores_acessos',
          'areas_comuns', 'reservas_areas_comuns', 'rondas_setores', 'rondas_pontos',
          'rondas_execucao', 'rondas_registros', 'materiais_posto',
          'checklist_manutencao', 'chamados_manutencao', 'ocorrencias', 'passagens_posto',
          'bancada_volumes', 'bancada_conferencias', 'passes_virtuais_qr', 'registros_acesso',
          'blacklist_bloqueios', 'pontos_acesso', 'historico_absoluto'
        )
        AND cmd IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
        AND NOT (
          tablename = 'historico_absoluto' AND cmd IN ('INSERT', 'UPDATE')
        )
        AND NOT (
          COALESCE(qual, '') ILIKE '%operador_tem_permissao_modulo%'
          OR COALESCE(with_check, '') ILIKE '%operador_tem_permissao_modulo%'
        )
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_policies
      WHERE schemaname = 'public'
        AND tablename IN (
          'moradores', 'encomendas_itens', 'lotes_re', 'entregadores',
          'custodia', 'chaves', 'movimentacao_chaves', 'prestadores', 'prestadores_acessos',
          'areas_comuns', 'reservas_areas_comuns', 'rondas_setores', 'rondas_pontos',
          'rondas_execucao', 'rondas_registros', 'materiais_posto',
          'checklist_manutencao', 'chamados_manutencao', 'ocorrencias', 'passagens_posto',
          'bancada_volumes', 'bancada_conferencias', 'passes_virtuais_qr', 'registros_acesso',
          'blacklist_bloqueios', 'pontos_acesso', 'historico_absoluto'
        )
        AND cmd IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
        AND NOT (
          tablename = 'historico_absoluto' AND cmd IN ('INSERT', 'UPDATE')
        )
        AND NOT (
          COALESCE(qual, '') ILIKE '%operador_tem_permissao_modulo%'
          OR COALESCE(with_check, '') ILIKE '%operador_tem_permissao_modulo%'
        )
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Comprova aplicacao efetiva da matriz funcional (operadores.permissoes) dentro do banco PostgreSQL.'

  UNION ALL
  SELECT
    13,
    '13. Tabelas filhas relacionais validam consistencia de condominio nas FKs (with_check)',
    (
      SELECT COUNT(*) FROM (
        SELECT unnest(ARRAY[
          'operador_condominios', 'lotes_re', 'encomendas_itens', 'custodia',
          'movimentacao_chaves', 'rondas_pontos', 'rondas_registros',
          'prestadores_acessos', 'reservas_areas_comuns', 'registros_acesso', 'passes_virtuais_qr'
        ]) AS tbl
      ) req
      WHERE EXISTS (
        SELECT 1 FROM information_schema.tables t WHERE t.table_schema = 'public' AND t.table_name = req.tbl
      )
      AND NOT (
        EXISTS (
          SELECT 1 FROM pg_policies p
          WHERE p.schemaname = 'public' AND p.tablename = req.tbl AND p.cmd = 'INSERT'
            AND COALESCE(p.with_check, '') ILIKE '%condominio_id%'
            AND COALESCE(p.with_check, '') ILIKE '%EXISTS%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_policies p
          WHERE p.schemaname = 'public' AND p.tablename = req.tbl AND p.cmd = 'UPDATE'
            AND COALESCE(p.with_check, '') ILIKE '%condominio_id%'
            AND COALESCE(p.with_check, '') ILIKE '%EXISTS%'
        )
      )
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM (
        SELECT unnest(ARRAY[
          'operador_condominios', 'lotes_re', 'encomendas_itens', 'custodia',
          'movimentacao_chaves', 'rondas_pontos', 'rondas_registros',
          'prestadores_acessos', 'reservas_areas_comuns', 'registros_acesso', 'passes_virtuais_qr'
        ]) AS tbl
      ) req
      WHERE EXISTS (
        SELECT 1 FROM information_schema.tables t WHERE t.table_schema = 'public' AND t.table_name = req.tbl
      )
      AND NOT (
        EXISTS (
          SELECT 1 FROM pg_policies p
          WHERE p.schemaname = 'public' AND p.tablename = req.tbl AND p.cmd = 'INSERT'
            AND COALESCE(p.with_check, '') ILIKE '%condominio_id%'
            AND COALESCE(p.with_check, '') ILIKE '%EXISTS%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_policies p
          WHERE p.schemaname = 'public' AND p.tablename = req.tbl AND p.cmd = 'UPDATE'
            AND COALESCE(p.with_check, '') ILIKE '%condominio_id%'
            AND COALESCE(p.with_check, '') ILIKE '%EXISTS%'
        )
      )
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Bloqueia em INSERT e UPDATE referencias a registros pais pertencentes a outro condominio.'

  UNION ALL
  SELECT
    14,
    '14. Bucket encomendas privado + 8 politicas exigindo operador ativo (operador_atual_id)',
    (
      SELECT CASE WHEN
        (SELECT COUNT(*) FROM storage.buckets WHERE id = 'encomendas' AND public = FALSE) = 1
        AND (SELECT COUNT(*) FROM pg_policies WHERE schemaname = 'storage' AND tablename = 'objects' AND roles::text ILIKE '%public%') = 0
        AND (
          SELECT COUNT(*) FROM pg_policies
          WHERE schemaname = 'storage' AND tablename = 'objects'
            AND policyname IN (
              'porttohub_storage_select', 'porttohub_storage_insert',
              'porttohub_storage_update', 'porttohub_storage_delete',
              'porttohub_storage_operadores_select', 'porttohub_storage_operadores_insert',
              'porttohub_storage_operadores_update', 'porttohub_storage_operadores_delete'
            )
            AND (
              COALESCE(qual, '') ILIKE '%operador_atual_id%'
              OR COALESCE(with_check, '') ILIKE '%operador_atual_id%'
            )
        ) = 8
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN
      (SELECT COUNT(*) FROM storage.buckets WHERE id = 'encomendas' AND public = FALSE) = 1
      AND (SELECT COUNT(*) FROM pg_policies WHERE schemaname = 'storage' AND tablename = 'objects' AND roles::text ILIKE '%public%') = 0
      AND (
        SELECT COUNT(*) FROM pg_policies
        WHERE schemaname = 'storage' AND tablename = 'objects'
          AND policyname IN (
            'porttohub_storage_select', 'porttohub_storage_insert',
            'porttohub_storage_update', 'porttohub_storage_delete',
            'porttohub_storage_operadores_select', 'porttohub_storage_operadores_insert',
            'porttohub_storage_operadores_update', 'porttohub_storage_operadores_delete'
          )
          AND (
            COALESCE(qual, '') ILIKE '%operador_atual_id%'
            OR COALESCE(with_check, '') ILIKE '%operador_atual_id%'
          )
      ) = 8
    THEN 'OK' ELSE 'FALHA' END,
    'Garante isolamento por condominio e pasta pessoal com verificacao de operador ativo nas 8 politicas.'

  UNION ALL
  SELECT
    15,
    '15. Constraint chk_passes_qr_usos_limite validada (convalidated = TRUE)',
    (
      SELECT COUNT(*) FROM pg_constraint
      WHERE conname = 'chk_passes_qr_usos_limite' AND convalidated = TRUE
    ),
    'Esperado: 1',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_constraint
      WHERE conname = 'chk_passes_qr_usos_limite' AND convalidated = TRUE
    ) = 1 THEN 'OK' ELSE 'ATENCAO' END,
    'Se ATENCAO, existem passes legados acima do limite ou VALIDATE CONSTRAINT pendente.'

  UNION ALL
  SELECT
    16,
    '16. Admin Geral ativo com acesso_global_condominios = TRUE e auth_user_id',
    (
      SELECT COUNT(*) FROM public.operadores
      WHERE COALESCE(acesso_global_condominios, FALSE) = TRUE
        AND COALESCE(ativo, TRUE) = TRUE
        AND auth_user_id IS NOT NULL
    ),
    'Esperado: >= 1',
    CASE WHEN (
      SELECT COUNT(*) FROM public.operadores
      WHERE COALESCE(acesso_global_condominios, FALSE) = TRUE
        AND COALESCE(ativo, TRUE) = TRUE
        AND auth_user_id IS NOT NULL
    ) >= 1 THEN 'OK' ELSE 'FALHA' END,
    'Confirma preservacao da conta administrativa principal vinculada ao Supabase Auth.'

  UNION ALL
  SELECT
    17,
    '17. Operadores ativos ainda sem auth_user_id vinculado',
    (
      SELECT COUNT(*) FROM public.operadores
      WHERE auth_user_id IS NULL AND COALESCE(ativo, TRUE) = TRUE
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM public.operadores
      WHERE auth_user_id IS NULL AND COALESCE(ativo, TRUE) = TRUE
    ) = 0 THEN 'OK' ELSE 'ATENCAO' END,
    'Contas ativas sem auth_user_id devem ser provisionadas pelo Admin ou desativadas.'

  UNION ALL
  SELECT
    18,
    '18. Cobertura de endpoints backend (/api/*) verificada fora do PostgreSQL',
    1::bigint,
    'Escopo: Runtime Worker/Node (ver npm test)',
    'ATENCAO'::text,
    'Esta auditoria SQL inspeciona apenas o PostgreSQL/Storage. A validacao de permissoes nos endpoints /api/* ocorre nos testes unitarios da aplicacao (npm test).'
)
SELECT
  ordem,
  verificacao,
  valor_encontrado,
  criterio,
  status,
  explicacao
FROM checks
ORDER BY ordem;
