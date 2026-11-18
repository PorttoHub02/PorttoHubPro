-- ============================================================================
-- PORTTOHUB PRO — 05_FUNCOES_AUTORIZACAO.sql
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   Cria funções PostgreSQL seguras (SECURITY DEFINER + search_path fixo) usadas
--   pelas políticas de RLS, triggers e pelo Storage para verificar:
--     1. Quem é o operador autenticado (`operador_atual_id`).
--     2. Se possui acesso global explícito (`operador_tem_acesso_global`).
--     3. Se pode gerenciar operadores globalmente (`operador_pode_gerenciar_operadores()` — SEM parâmetro, EXCLUSIVA do acesso global).
--     4. Se pode gerenciar operadores localmente (`operador_pode_gerenciar_operadores(TEXT/UUID)` — COM p_condominio_id, admin_geral ou admin_condominio do próprio condomínio principal).
--     5. Se pode acessar dados de um condomínio (`operador_pode_acessar_condominio`).
--     6. Correspondência segura de e-mail em auth.users (`operador_auth_email_corresponde`), restrita ao próprio auth.uid(), service_role ou sessão SQL administrativa.
--     7. Avaliação de permissões funcionais por módulo e ação (`operador_tem_permissao_modulo`), espelhando operadores.permissoes e perfis oficiais.
--     8. Guardas de imutabilidade de perfil próprio (incluindo `permissoes`) e edição restrita de subordinados.
--
-- REGRAS OFICIAIS DE SEGURANCA:
--   - Perfis padronizados: admin_geral, admin_condominio, supervisor, operador (e sindico em somente leitura).
--   - Nunca utiliza nivel_acesso isoladamente para conceder privilégios globais ou administrativos.
--   - SUPERVISOR não recebe poderes administrativos de gestão de operadores automaticamente.
--   - ADMIN_CONDOMINIO gerencia somente operadores do seu próprio condomínio principal,
--     não concede acesso global, não cria admin_geral, não altera o próprio perfil/privilégios/permissões/vínculo
--     e não transfere operadores entre condomínios.
--   - Execução revogada explicitamente de PUBLIC e anon em todas as funções.
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

-- Auxiliar protegido: valida correspondência de e-mail em auth.users SEM permitir sondagem de terceiros por usuários comuns.
-- Aceita apenas: próprio auth.uid(), JWT comprovadamente service_role ou sessão SQL administrativa direta (auth.uid() IS NULL).
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

-- Verifica permissão funcional por módulo e ação com base em operadores.permissoes + regras oficiais do perfil.
-- Espelha as chaves oficiais de src/services/permissoesService.ts sem inventar nomes.
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

  -- Sinônimos oficiais de módulo (permissoesService.ts)
  IF v_mod = 'prestadores' THEN v_mod := 'autorizados'; END IF;
  IF v_mod = 'passagem' THEN v_mod := 'passagem_posto'; END IF;

  v_perfil := lower(trim(COALESCE(v_op.perfil, '')));
  v_nivel := v_op.nivel_acesso;

  v_eh_admin_condo := (v_perfil IN ('admin_condominio', 'admin_local', 'admin', 'master'));
  v_eh_supervisor := (NOT v_eh_admin_condo AND (v_perfil = 'supervisor' OR v_nivel = 2));
  v_eh_sindico := (NOT v_eh_admin_condo AND NOT v_eh_supervisor AND (v_perfil LIKE '%sind%' OR v_nivel = 4));

  -- Regras estritas de segurança independentes de JSONB customizado
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

  -- Regra estrita do perfil Síndico (Nível 4): consulta nos módulos ativos, escrita apenas em ocorrências (criar/resolver)
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

  -- Resolução de permissões JSONB específicas do operador (operadores.permissoes)
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

      -- Aliases oficiais de ação por módulo (resolverAcaoEmPermissoesModulo)
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

  -- Matriz padrão oficial (NIVEIS_PADRAO: nivel_1 admin_condominio, nivel_2 supervisor, nivel_3 operador)
  IF v_acao IN ('visualizar', 'historico', 'relatorio', 'ver_feed', 'auditoria', 'visualizar_moradores') THEN
    IF v_mod = 'encomendas' AND v_acao = 'dossie' AND NOT v_eh_admin_condo AND NOT v_eh_supervisor THEN
      RETURN FALSE;
    END IF;
    RETURN TRUE;
  END IF;

  IF v_eh_admin_condo THEN
    IF v_mod = 'historico_absoluto' THEN
      RETURN FALSE;
    END IF;
    IF v_mod = 'cadastros' AND v_acao IN ('excluir', 'excluir_morador', 'excluir_operadores', 'condominios', 'gerenciar_niveis') THEN
      RETURN FALSE;
    END IF;
    IF v_mod = 'reservas' AND v_acao = 'cancelar' THEN
      RETURN TRUE;
    END IF;
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

  -- Perfil Operador / Porteiro (Nível 3)
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

-- Impede que operadores não globais (inclusive admin_condominio) alterem próprio perfil, privilégios, permissões JSONB ou vínculo condominial
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

-- Revoga execução de PUBLIC e anon explicitamente e libera apenas para authenticated / service_role
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
    'operador_auth_email_corresponde',
    'operador_tem_permissao_modulo',
    'operador_preserva_proprio_perfil',
    'operador_pode_editar_alvo_local'
  )
ORDER BY p.proname, argumentos;
