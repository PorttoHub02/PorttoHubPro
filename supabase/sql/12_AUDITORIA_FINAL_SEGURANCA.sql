-- ============================================================================
-- PORTTOHUB PRO — 12_AUDITORIA_FINAL_SEGURANCA.sql (100% SOMENTE LEITURA)
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   Auditoria completa, objetiva e não destrutiva do banco Supabase após a
--   aplicação do script 11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql (ou instalação
--   completa 01–08).
--
-- STATUS PADRONIZADOS:
--   - 'OK'          : Requisito verificado e em conformidade
--   - 'ATENÇÃO'     : Requer revisão operacional ou item extra detectado
--   - 'FALHA'       : Vulnerabilidade ou ausência crítica detectada
--   - 'NÃO TESTADO' : Item fora do escopo SQL direto (ex.: rotas /api/* via npm test)
--
-- NOTA SOBRE INSPECÇÃO:
--   Checks que leem pg_get_functiondef(...) são explicitamente marcados como
--   [VERIFICAÇÃO ESTRUTURAL], complementados por checagens reais de privilégios
--   (has_function_privilege, has_schema_privilege, role_table_grants, pg_trigger).
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

-- B. DIAGNÓSTICO DE MODO E PRIVILÉGIOS DE TODAS AS FUNÇÕES CRÍTICAS E TRIGGERS
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
    'operador_pode_registrar_auditoria',
    'operador_preserva_proprio_perfil',
    'operador_pode_editar_alvo_local',
    'proteger_campos_operador',
    'proteger_campos_passe_qr',
    'proteger_autoria_historico_absoluto',
    'proteger_autoria_registros_acesso',
    'validar_e_consumir_passe_qr'
  )
ORDER BY p.proname, argumentos;

-- C. INVENTÁRIO POR TABELA (35 CANÔNICAS vs EVENTUAIS TABELAS EXTRAS PRESERVADAS)
WITH canonicas AS (
  SELECT unnest(ARRAY[
    'condominios', 'operadores', 'operador_condominios',
    'configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'pontos_acesso',
    'historico_absoluto', 'passes_virtuais_qr', 'registros_acesso',
    'encomendas_itens', 'movimentacao_chaves', 'prestadores_acessos', 'reservas_areas_comuns',
    'moradores', 'entregadores', 'lotes_re', 'custodia', 'materiais_posto',
    'chaves', 'checklist_manutencao', 'chamados_manutencao', 'rondas_setores',
    'rondas_pontos', 'rondas_execucao', 'rondas_registros', 'ocorrencias',
    'passagens_posto', 'prestadores', 'lembretes_portaria', 'bancada_volumes',
    'bancada_conferencias', 'agenda_emergencia', 'areas_comuns', 'blacklist_bloqueios'
  ]) AS nome
)
SELECT
  c.relname AS tabela,
  CASE WHEN cn.nome IS NOT NULL THEN 'OFICIAL_35' ELSE 'EXTRA_PRESERVADA' END AS classificacao,
  c.relrowsecurity AS rls_ativo,
  COUNT(p.policyname) AS qtd_politicas,
  COUNT(p.policyname) FILTER (WHERE p.cmd = 'ALL') AS qtd_for_all,
  BOOL_OR(
    COALESCE(p.qual, '') ILIKE '%operador_tem_permissao_modulo%'
    OR COALESCE(p.with_check, '') ILIKE '%operador_tem_permissao_modulo%'
  ) AS usa_permissao_modulo
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN canonicas cn ON cn.nome = c.relname
LEFT JOIN pg_policies p ON p.schemaname = 'public' AND p.tablename = c.relname
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
GROUP BY c.relname, cn.nome, c.relrowsecurity
ORDER BY classificacao, c.relname;

-- D. QUADRO CONSOLIDADO DA AUDITORIA FINAL DE SEGURANÇA
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
    'Checagem real de catálogo (prosecdef + pg_trigger): impede auto-bypass via current_user=postgres em operadores.'::text AS explicacao

  UNION ALL
  SELECT
    2,
    '2. [VERIFICAÇÃO ESTRUTURAL] Coluna permissoes + perfil + vínculo protegidos na auto-edição',
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
    'VERIFICAÇÃO ESTRUTURAL (pg_get_functiondef): confirma bloqueio de auto-alteração de permissoes, vínculo condominial e conta inativa.'

  UNION ALL
  SELECT
    3,
    '3. Trigger proteger_campos_passe_qr (SECURITY INVOKER + ativa) [VERIFICAÇÃO ESTRUTURAL usos/status/token]',
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
    'Combina catálogo real (INVOKER + trigger ativa) com VERIFICAÇÃO ESTRUTURAL dos campos protegidos em passes_virtuais_qr.'

  UNION ALL
  SELECT
    4,
    '4. Isolamento do schema/tabela interna porttohub_internal.passe_qr_tx_autorizacao',
    (
      SELECT CASE WHEN
        EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'porttohub_internal')
        AND to_regclass('porttohub_internal.passe_qr_tx_autorizacao') IS NOT NULL
        AND NOT has_schema_privilege('public', 'porttohub_internal', 'USAGE')
        AND NOT has_schema_privilege('anon', 'porttohub_internal', 'USAGE')
        AND NOT has_schema_privilege('authenticated', 'porttohub_internal', 'USAGE')
        AND NOT has_table_privilege('anon', 'porttohub_internal.passe_qr_tx_autorizacao', 'SELECT')
        AND NOT has_table_privilege('authenticated', 'porttohub_internal.passe_qr_tx_autorizacao', 'SELECT')
        AND NOT has_table_privilege('authenticated', 'porttohub_internal.passe_qr_tx_autorizacao', 'INSERT')
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN
      EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'porttohub_internal')
      AND to_regclass('porttohub_internal.passe_qr_tx_autorizacao') IS NOT NULL
      AND NOT has_schema_privilege('public', 'porttohub_internal', 'USAGE')
      AND NOT has_schema_privilege('anon', 'porttohub_internal', 'USAGE')
      AND NOT has_schema_privilege('authenticated', 'porttohub_internal', 'USAGE')
      AND NOT has_table_privilege('anon', 'porttohub_internal.passe_qr_tx_autorizacao', 'SELECT')
      AND NOT has_table_privilege('authenticated', 'porttohub_internal.passe_qr_tx_autorizacao', 'SELECT')
      AND NOT has_table_privilege('authenticated', 'porttohub_internal.passe_qr_tx_autorizacao', 'INSERT')
    THEN 'OK' ELSE 'FALHA' END,
    'Checagem real de privilégios: comprova que nenhum papel cliente (PUBLIC/anon/authenticated) acessa o marcador transacional de Passe QR.'

  UNION ALL
  SELECT
    5,
    '5. [VERIFICAÇÃO ESTRUTURAL] RPC validar_e_consumir_passe_qr sem bypass current_user nem GUC cliente',
    (
      SELECT CASE WHEN
        EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'validar_e_consumir_passe_qr'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%current_user NOT IN%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%porttohub.rpc_passe_qr_consumo%'
            AND pg_get_functiondef(p.oid) ILIKE '%service_role%'
            AND pg_get_functiondef(p.oid) ILIKE '%operador_tem_permissao_modulo%'
            AND pg_get_functiondef(p.oid) ILIKE '%o.auth_user_id = auth.uid()%'
            AND pg_get_functiondef(p.oid) ILIKE '%FOR UPDATE%'
            AND pg_get_functiondef(p.oid) ILIKE '%passe_qr_tx_autorizacao%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'proteger_campos_passe_qr'
            AND pg_get_functiondef(p.oid) ILIKE '%passe_qr_tx_autorizacao%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%porttohub.rpc_passe_qr_consumo%'
        )
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN
      EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'validar_e_consumir_passe_qr'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%current_user NOT IN%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%porttohub.rpc_passe_qr_consumo%'
          AND pg_get_functiondef(p.oid) ILIKE '%service_role%'
          AND pg_get_functiondef(p.oid) ILIKE '%operador_tem_permissao_modulo%'
          AND pg_get_functiondef(p.oid) ILIKE '%o.auth_user_id = auth.uid()%'
          AND pg_get_functiondef(p.oid) ILIKE '%FOR UPDATE%'
          AND pg_get_functiondef(p.oid) ILIKE '%passe_qr_tx_autorizacao%'
      )
      AND EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'proteger_campos_passe_qr'
          AND pg_get_functiondef(p.oid) ILIKE '%passe_qr_tx_autorizacao%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%porttohub.rpc_passe_qr_consumo%'
      )
    THEN 'OK' ELSE 'FALHA' END,
    'VERIFICAÇÃO ESTRUTURAL (pg_get_functiondef): confirma marcador em tabela privada (zero set_config GUC), lock FOR UPDATE e service_role/auth.uid().'

  UNION ALL
  SELECT
    6,
    '6. Triggers de autoria em historico_absoluto e registros_acesso (SECURITY INVOKER + [VERIFICAÇÃO ESTRUTURAL] autorização de módulo/ação)',
    (
      SELECT CASE WHEN
        EXISTS (
          SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'proteger_autoria_historico_absoluto'
            AND p.prosecdef = FALSE
            AND pg_get_functiondef(p.oid) ILIKE '%operador_pode_registrar_auditoria%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'operador_pode_registrar_auditoria'
            AND pg_get_functiondef(p.oid) ILIKE '%operador_tem_permissao_modulo%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relname = 'historico_absoluto'
            AND t.tgname = 'trg_proteger_autoria_historico_absoluto' AND t.tgenabled IN ('O', 'A')
        )
        AND EXISTS (
          SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public' AND p.proname = 'proteger_autoria_registros_acesso' AND p.prosecdef = FALSE
        )
        AND EXISTS (
          SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relname = 'registros_acesso'
            AND t.tgname = 'trg_proteger_autoria_registros_acesso' AND t.tgenabled IN ('O', 'A')
        )
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN
      EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'proteger_autoria_historico_absoluto'
          AND p.prosecdef = FALSE
          AND pg_get_functiondef(p.oid) ILIKE '%operador_pode_registrar_auditoria%'
      )
      AND EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'operador_pode_registrar_auditoria'
          AND pg_get_functiondef(p.oid) ILIKE '%operador_tem_permissao_modulo%'
      )
      AND EXISTS (
        SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'historico_absoluto'
          AND t.tgname = 'trg_proteger_autoria_historico_absoluto' AND t.tgenabled IN ('O', 'A')
      )
      AND EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname = 'proteger_autoria_registros_acesso' AND p.prosecdef = FALSE
      )
      AND EXISTS (
        SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'registros_acesso'
          AND t.tgname = 'trg_proteger_autoria_registros_acesso' AND t.tgenabled IN ('O', 'A')
      )
    THEN 'OK' ELSE 'FALHA' END,
    'Checagem de catálogo + VERIFICAÇÃO ESTRUTURAL: impede spoofing de operador/timestamp e gravação de eventos de auditoria sem permissão do módulo/ação.'

  UNION ALL
  SELECT
    7,
    '7. [VERIFICAÇÃO ESTRUTURAL] Funções de autorização e matriz unificada (somente admin_geral / admin_condominio, sem admin_local/admin/master nem promoção por nivel_acesso)',
    (
      SELECT CASE WHEN
        EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'operador_tem_permissao_modulo'
            AND pg_get_functiondef(p.oid) ILIKE '%nivel_acesso_custom_id%'
            AND pg_get_functiondef(p.oid) ILIKE '%configuracoes%'
            AND pg_get_functiondef(p.oid) ILIKE '%niveis_acesso%'
            AND pg_get_functiondef(p.oid) ILIKE '%v_eh_nivel_custom%'
            AND pg_get_functiondef(p.oid) ILIKE '%v_perfil = ''admin_geral''%'
            AND pg_get_functiondef(p.oid) ILIKE '%v_perfil = ''admin_condominio''%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%admin_local%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%''admin''%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%''master''%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%OR v_nivel_id = ''nivel_1''%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%OR v_nivel = 2%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%OR v_nivel = 4%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'operador_tem_acesso_global'
            AND pg_get_functiondef(p.oid) ~* 'lower\(trim\(coalesce\([^,]*perfil,\s*''''\)\)\)\s*=\s*''admin_geral'''
            AND pg_get_functiondef(p.oid) ~* 'coalesce\([^,]*acesso_global_condominios,\s*false\)\s*=\s*true'
            AND pg_get_functiondef(p.oid) ~* 'coalesce\([^,]*ativo,\s*true\)\s*=\s*true'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%admin_local%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%''admin''%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%''master''%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'operador_pode_gerenciar_operadores'
            AND pg_get_function_identity_arguments(p.oid) = 'p_condominio_id text'
            AND pg_get_functiondef(p.oid) ILIKE '%''admin_geral''%'
            AND pg_get_functiondef(p.oid) ILIKE '%''admin_condominio''%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%admin_local%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%''admin''%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%''master''%'
        )
        AND EXISTS (
          SELECT 1 FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'operador_pode_acessar_condominio'
            AND pg_get_function_identity_arguments(p.oid) = 'p_condominio_id text'
            AND pg_get_functiondef(p.oid) ILIKE '%''admin_geral''%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%admin_local%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%''admin''%'
            AND pg_get_functiondef(p.oid) NOT ILIKE '%''master''%'
        )
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN
      EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'operador_tem_permissao_modulo'
          AND pg_get_functiondef(p.oid) ILIKE '%nivel_acesso_custom_id%'
          AND pg_get_functiondef(p.oid) ILIKE '%configuracoes%'
          AND pg_get_functiondef(p.oid) ILIKE '%niveis_acesso%'
          AND pg_get_functiondef(p.oid) ILIKE '%v_eh_nivel_custom%'
          AND pg_get_functiondef(p.oid) ILIKE '%v_perfil = ''admin_geral''%'
          AND pg_get_functiondef(p.oid) ILIKE '%v_perfil = ''admin_condominio''%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%admin_local%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%''admin''%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%''master''%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%OR v_nivel_id = ''nivel_1''%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%OR v_nivel = 2%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%OR v_nivel = 4%'
      )
      AND EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'operador_tem_acesso_global'
          AND pg_get_functiondef(p.oid) ~* 'lower\(trim\(coalesce\([^,]*perfil,\s*''''\)\)\)\s*=\s*''admin_geral'''
          AND pg_get_functiondef(p.oid) ~* 'coalesce\([^,]*acesso_global_condominios,\s*false\)\s*=\s*true'
          AND pg_get_functiondef(p.oid) ~* 'coalesce\([^,]*ativo,\s*true\)\s*=\s*true'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%admin_local%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%''admin''%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%''master''%'
      )
      AND EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'operador_pode_gerenciar_operadores'
          AND pg_get_function_identity_arguments(p.oid) = 'p_condominio_id text'
          AND pg_get_functiondef(p.oid) ILIKE '%''admin_geral''%'
          AND pg_get_functiondef(p.oid) ILIKE '%''admin_condominio''%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%admin_local%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%''admin''%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%''master''%'
      )
      AND EXISTS (
        SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'operador_pode_acessar_condominio'
          AND pg_get_function_identity_arguments(p.oid) = 'p_condominio_id text'
          AND pg_get_functiondef(p.oid) ILIKE '%''admin_geral''%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%admin_local%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%''admin''%'
          AND pg_get_functiondef(p.oid) NOT ILIKE '%''master''%'
      )
    THEN 'OK' ELSE 'FALHA' END,
    'VERIFICAÇÃO ESTRUTURAL (pg_get_functiondef): confirma acesso global exclusivo de admin_geral, administração local exclusiva de admin_condominio, ausência de admin_local/admin/master e bloqueio de promoção por nivel_acesso=0/1.'

  UNION ALL
  SELECT
    8,
    '8. Todas as funções críticas/triggers/RPC sem EXECUTE para anon ou PUBLIC',
    (
      SELECT COUNT(*) FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname IN (
          'operador_atual_id', 'operador_tem_acesso_global', 'operador_pode_gerenciar_operadores',
          'operador_pode_acessar_condominio', 'operador_auth_email_corresponde',
          'operador_tem_permissao_modulo', 'operador_pode_registrar_auditoria',
          'operador_preserva_proprio_perfil', 'operador_pode_editar_alvo_local',
          'proteger_campos_operador', 'proteger_campos_passe_qr',
          'proteger_autoria_historico_absoluto', 'proteger_autoria_registros_acesso',
          'validar_e_consumir_passe_qr'
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
          'operador_tem_permissao_modulo', 'operador_pode_registrar_auditoria',
          'operador_preserva_proprio_perfil', 'operador_pode_editar_alvo_local',
          'proteger_campos_operador', 'proteger_campos_passe_qr',
          'proteger_autoria_historico_absoluto', 'proteger_autoria_registros_acesso',
          'validar_e_consumir_passe_qr'
        )
        AND (
          has_function_privilege('anon', p.oid, 'EXECUTE')
          OR has_function_privilege('public', p.oid, 'EXECUTE')
        )
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Checagem real de privilégios (has_function_privilege) em todas as funções críticas, triggers e RPCs.'

  UNION ALL
  SELECT
    9,
    '9. [VERIFICAÇÃO ESTRUTURAL] operador_auth_email_corresponde protege auth.users contra sondagem',
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
    'VERIFICAÇÃO ESTRUTURAL (pg_get_functiondef): restringe leitura de auth.users ao próprio auth.uid(), service_role ou sessão SQL administrativa.'

  UNION ALL
  SELECT
    10,
    '10. Políticas permissivas USING (true) / WITH CHECK (true) em public ou storage',
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
    'Checagem real de catálogo: nenhuma política permissiva irrestrita deve existir.'

  UNION ALL
  SELECT
    11,
    '11. As 35 tabelas oficiais com RLS ativo, políticas presentes e zero FOR ALL',
    (
      WITH canonicas AS (
        SELECT unnest(ARRAY[
          'condominios', 'operadores', 'operador_condominios',
          'configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'pontos_acesso',
          'historico_absoluto', 'passes_virtuais_qr', 'registros_acesso',
          'encomendas_itens', 'movimentacao_chaves', 'prestadores_acessos', 'reservas_areas_comuns',
          'moradores', 'entregadores', 'lotes_re', 'custodia', 'materiais_posto',
          'chaves', 'checklist_manutencao', 'chamados_manutencao', 'rondas_setores',
          'rondas_pontos', 'rondas_execucao', 'rondas_registros', 'ocorrencias',
          'passagens_posto', 'prestadores', 'lembretes_portaria', 'bancada_volumes',
          'bancada_conferencias', 'agenda_emergencia', 'areas_comuns', 'blacklist_bloqueios'
        ]) AS nome
      )
      SELECT COUNT(*) FROM canonicas cn
      LEFT JOIN pg_class c ON c.relname = cn.nome AND c.relkind = 'r'
      LEFT JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
      WHERE n.oid IS NULL
        OR c.relrowsecurity = FALSE
        OR NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = cn.nome)
        OR EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = cn.nome AND p.cmd = 'ALL')
    ),
    'Esperado: 0 pendências nas 35 oficiais',
    CASE WHEN (
      WITH canonicas AS (
        SELECT unnest(ARRAY[
          'condominios', 'operadores', 'operador_condominios',
          'configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'pontos_acesso',
          'historico_absoluto', 'passes_virtuais_qr', 'registros_acesso',
          'encomendas_itens', 'movimentacao_chaves', 'prestadores_acessos', 'reservas_areas_comuns',
          'moradores', 'entregadores', 'lotes_re', 'custodia', 'materiais_posto',
          'chaves', 'checklist_manutencao', 'chamados_manutencao', 'rondas_setores',
          'rondas_pontos', 'rondas_execucao', 'rondas_registros', 'ocorrencias',
          'passagens_posto', 'prestadores', 'lembretes_portaria', 'bancada_volumes',
          'bancada_conferencias', 'agenda_emergencia', 'areas_comuns', 'blacklist_bloqueios'
        ]) AS nome
      )
      SELECT COUNT(*) FROM canonicas cn
      LEFT JOIN pg_class c ON c.relname = cn.nome AND c.relkind = 'r'
      LEFT JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
      WHERE n.oid IS NULL
        OR c.relrowsecurity = FALSE
        OR NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = cn.nome)
        OR EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = cn.nome AND p.cmd = 'ALL')
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Valida estritamente as 35 tabelas oficiais (RLS ativo, granularidade e existência).'

  UNION ALL
  SELECT
    12,
    '12. Grants restritos nas 35 tabelas oficiais (zero anon/PUBLIC/TRUNCATE/TRIGGER/REFERENCES)',
    (
      SELECT COUNT(*) FROM information_schema.role_table_grants
      WHERE table_schema = 'public'
        AND table_name IN (
          'condominios', 'operadores', 'operador_condominios',
          'configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'pontos_acesso',
          'historico_absoluto', 'passes_virtuais_qr', 'registros_acesso',
          'encomendas_itens', 'movimentacao_chaves', 'prestadores_acessos', 'reservas_areas_comuns',
          'moradores', 'entregadores', 'lotes_re', 'custodia', 'materiais_posto',
          'chaves', 'checklist_manutencao', 'chamados_manutencao', 'rondas_setores',
          'rondas_pontos', 'rondas_execucao', 'rondas_registros', 'ocorrencias',
          'passagens_posto', 'prestadores', 'lembretes_portaria', 'bancada_volumes',
          'bancada_conferencias', 'agenda_emergencia', 'areas_comuns', 'blacklist_bloqueios'
        )
        AND (
          grantee IN ('anon', 'PUBLIC')
          OR (grantee = 'authenticated' AND privilege_type IN ('TRUNCATE', 'TRIGGER', 'REFERENCES'))
        )
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM information_schema.role_table_grants
      WHERE table_schema = 'public'
        AND table_name IN (
          'condominios', 'operadores', 'operador_condominios',
          'configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'pontos_acesso',
          'historico_absoluto', 'passes_virtuais_qr', 'registros_acesso',
          'encomendas_itens', 'movimentacao_chaves', 'prestadores_acessos', 'reservas_areas_comuns',
          'moradores', 'entregadores', 'lotes_re', 'custodia', 'materiais_posto',
          'chaves', 'checklist_manutencao', 'chamados_manutencao', 'rondas_setores',
          'rondas_pontos', 'rondas_execucao', 'rondas_registros', 'ocorrencias',
          'passagens_posto', 'prestadores', 'lembretes_portaria', 'bancada_volumes',
          'bancada_conferencias', 'agenda_emergencia', 'areas_comuns', 'blacklist_bloqueios'
        )
        AND (
          grantee IN ('anon', 'PUBLIC')
          OR (grantee = 'authenticated' AND privilege_type IN ('TRUNCATE', 'TRIGGER', 'REFERENCES'))
        )
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Checagem real em role_table_grants restrita às 35 tabelas oficiais.'

  UNION ALL
  SELECT
    13,
    '13. Tabelas extras fora das 35 oficiais preservadas intactas em public',
    (
      SELECT COUNT(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public'
        AND c.relkind = 'r'
        AND c.relname NOT IN (
          'condominios', 'operadores', 'operador_condominios',
          'configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'pontos_acesso',
          'historico_absoluto', 'passes_virtuais_qr', 'registros_acesso',
          'encomendas_itens', 'movimentacao_chaves', 'prestadores_acessos', 'reservas_areas_comuns',
          'moradores', 'entregadores', 'lotes_re', 'custodia', 'materiais_posto',
          'chaves', 'checklist_manutencao', 'chamados_manutencao', 'rondas_setores',
          'rondas_pontos', 'rondas_execucao', 'rondas_registros', 'ocorrencias',
          'passagens_posto', 'prestadores', 'lembretes_portaria', 'bancada_volumes',
          'bancada_conferencias', 'agenda_emergencia', 'areas_comuns', 'blacklist_bloqueios'
        )
    ),
    'Informativo: 0 = somente 35 oficiais; > 0 = revisar extras no Quadro C',
    CASE WHEN (
      SELECT COUNT(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public'
        AND c.relkind = 'r'
        AND c.relname NOT IN (
          'condominios', 'operadores', 'operador_condominios',
          'configuracoes', 'templates_whatsapp', 'locais_armazenamento', 'pontos_acesso',
          'historico_absoluto', 'passes_virtuais_qr', 'registros_acesso',
          'encomendas_itens', 'movimentacao_chaves', 'prestadores_acessos', 'reservas_areas_comuns',
          'moradores', 'entregadores', 'lotes_re', 'custodia', 'materiais_posto',
          'chaves', 'checklist_manutencao', 'chamados_manutencao', 'rondas_setores',
          'rondas_pontos', 'rondas_execucao', 'rondas_registros', 'ocorrencias',
          'passagens_posto', 'prestadores', 'lembretes_portaria', 'bancada_volumes',
          'bancada_conferencias', 'agenda_emergencia', 'areas_comuns', 'blacklist_bloqueios'
        )
    ) = 0 THEN 'OK' ELSE 'ATENÇÃO' END,
    'Se ATENÇÃO, há tabelas auxiliares fora das 35 oficiais (não modificadas pela migração 11); inspecione o Quadro C.'

  UNION ALL
  SELECT
    14,
    '14. Políticas de módulos usam operador_tem_permissao_modulo + historico_absoluto exige autoria e operador_pode_registrar_auditoria',
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
        AND (
          (
            tablename = 'historico_absoluto' AND cmd = 'INSERT'
            AND NOT (
              COALESCE(with_check, '') ILIKE '%operador_atual_id%'
              AND COALESCE(with_check, '') ILIKE '%operador_pode_acessar_condominio%'
              AND COALESCE(with_check, '') ILIKE '%operador_pode_registrar_auditoria%'
            )
          )
          OR (
            NOT (tablename = 'historico_absoluto' AND cmd IN ('INSERT', 'UPDATE'))
            AND NOT (
              COALESCE(qual, '') ILIKE '%operador_tem_permissao_modulo%'
              OR COALESCE(with_check, '') ILIKE '%operador_tem_permissao_modulo%'
            )
          )
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
        AND (
          (
            tablename = 'historico_absoluto' AND cmd = 'INSERT'
            AND NOT (
              COALESCE(with_check, '') ILIKE '%operador_atual_id%'
              AND COALESCE(with_check, '') ILIKE '%operador_pode_acessar_condominio%'
              AND COALESCE(with_check, '') ILIKE '%operador_pode_registrar_auditoria%'
            )
          )
          OR (
            NOT (tablename = 'historico_absoluto' AND cmd IN ('INSERT', 'UPDATE'))
            AND NOT (
              COALESCE(qual, '') ILIKE '%operador_tem_permissao_modulo%'
              OR COALESCE(with_check, '') ILIKE '%operador_tem_permissao_modulo%'
            )
          )
        )
    ) = 0 THEN 'OK' ELSE 'FALHA' END,
    'Comprova enforcement de matriz unificada nas políticas RLS operacionais e validação de autoria + módulo/ação em historico_absoluto.'

  UNION ALL
  SELECT
    15,
    '15. Tabelas filhas relacionais validam consistência de condominio nas FKs',
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
    'Impede referências cross-condominio em registros filhos durante INSERT e UPDATE.'

  UNION ALL
  SELECT
    16,
    '16. Bucket encomendas privado + 8 políticas exigindo operador ativo (operador_atual_id)',
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
    'Garante bucket privado e isolamento nas 8 políticas de Storage.'

  UNION ALL
  SELECT
    17,
    '17. Constraint chk_passes_qr_usos_limite validada + Admin Geral (perfil=admin_geral) ativo',
    (
      SELECT CASE WHEN
        (SELECT COUNT(*) FROM pg_constraint WHERE conname = 'chk_passes_qr_usos_limite' AND convalidated = TRUE) = 1
        AND (
          SELECT COUNT(*) FROM public.operadores
          WHERE lower(trim(COALESCE(perfil, ''))) = 'admin_geral'
            AND COALESCE(acesso_global_condominios, FALSE) = TRUE
            AND COALESCE(ativo, TRUE) = TRUE
            AND auth_user_id IS NOT NULL
        ) >= 1
        AND (
          SELECT COUNT(*) FROM public.operadores
          WHERE auth_user_id IS NULL AND COALESCE(ativo, TRUE) = TRUE
        ) = 0
      THEN 1 ELSE 0 END
    )::bigint,
    'Esperado: 1',
    CASE WHEN (
      SELECT COUNT(*) FROM public.operadores
      WHERE lower(trim(COALESCE(perfil, ''))) = 'admin_geral'
        AND COALESCE(acesso_global_condominios, FALSE) = TRUE
        AND COALESCE(ativo, TRUE) = TRUE
        AND auth_user_id IS NOT NULL
    ) < 1 THEN 'FALHA'
    WHEN (
      SELECT COUNT(*) FROM pg_constraint WHERE conname = 'chk_passes_qr_usos_limite' AND convalidated = TRUE
    ) = 1
    AND (
      SELECT COUNT(*) FROM public.operadores WHERE auth_user_id IS NULL AND COALESCE(ativo, TRUE) = TRUE
    ) = 0 THEN 'OK'
    ELSE 'ATENÇÃO' END,
    'FALHA se faltar admin_geral ativo com acesso_global_condominios=TRUE e Auth; ATENÇÃO se chk_passes_qr_usos_limite não estiver validada ou houver operadores ativos sem auth_user_id.'

  UNION ALL
  SELECT
    18,
    '18. Consistência de classificação em public.operadores (sem global fora de admin_geral, sem perfis legados admin_local/admin/master nem nivel_acesso=0/1 em não-admins)',
    (
      SELECT COUNT(*) FROM public.operadores
      WHERE COALESCE(ativo, TRUE) = TRUE
        AND (
          (COALESCE(acesso_global_condominios, FALSE) = TRUE AND lower(trim(COALESCE(perfil, ''))) <> 'admin_geral')
          OR lower(trim(COALESCE(perfil, ''))) IN ('admin_local', 'admin', 'master')
          OR (
            lower(trim(COALESCE(perfil, ''))) IN ('operador', 'porteiro', 'supervisor', 'sindico', 'síndico')
            AND (
              nivel_acesso IN (0, 1)
              OR lower(trim(COALESCE(nivel_acesso_custom_id, ''))) IN ('0', '1', 'nivel_0', 'nivel_1')
            )
          )
        )
    ),
    'Esperado: 0',
    CASE WHEN (
      SELECT COUNT(*) FROM public.operadores
      WHERE COALESCE(ativo, TRUE) = TRUE
        AND (
          (COALESCE(acesso_global_condominios, FALSE) = TRUE AND lower(trim(COALESCE(perfil, ''))) <> 'admin_geral')
          OR lower(trim(COALESCE(perfil, ''))) IN ('admin_local', 'admin', 'master')
          OR (
            lower(trim(COALESCE(perfil, ''))) IN ('operador', 'porteiro', 'supervisor', 'sindico', 'síndico')
            AND (
              nivel_acesso IN (0, 1)
              OR lower(trim(COALESCE(nivel_acesso_custom_id, ''))) IN ('0', '1', 'nivel_0', 'nivel_1')
            )
          )
        )
    ) = 0 THEN 'OK' ELSE 'ATENÇÃO' END,
    'Identifica registros legados inconsistentes em operadores (perfis admin_local/admin/master, global fora de admin_geral ou nivel_acesso=0/1 em não-admins).'

  UNION ALL
  SELECT
    19,
    '19. Cobertura runtime de endpoints backend (/api/*) e testes ao vivo de RLS',
    0::bigint,
    'Escopo: Runtime Worker/Node (executar npm test e npm run test:integration)',
    'NÃO TESTADO'::text,
    'NÃO TESTADO em SQL estático: esta auditoria inspeciona apenas o catálogo PostgreSQL/Storage. Valide endpoints /api/* com npm test e RLS ao vivo com npm run test:integration.'
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
