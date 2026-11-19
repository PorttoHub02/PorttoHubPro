-- ============================================================================
-- PORTTOHUB PRO — 05B_FUNCOES_PASSE_QR.sql
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   Cria a função PostgreSQL transacional `public.validar_e_consumir_passe_qr`
--   para validar e consumir Passes Virtuais QR de forma atômica no banco,
--   impedindo corrida concorrente (race condition) de `max_usos`, reutilização
--   após limite, acesso fora da janela de data/horário, vazamento entre
--   condomínios, bypass anônimo e falsificação (spoofing) de operador.
--
-- SEGURANÇA REFORÇADA:
--   - Sem exceção baseada em `current_user` (que em SECURITY DEFINER vira
--     o proprietário 'postgres'). Sem `auth.uid()`, aceita APENAS JWT
--     comprovadamente `service_role`.
--   - Usuário autenticado exige operador ativo, vínculo ao condomínio e
--     permissão no módulo `controle_acesso` (`operador_tem_permissao_modulo`).
--   - Registra autorização transacional interna em tabela privada do schema
--     `porttohub_internal.passe_qr_tx_autorizacao` (sem acesso para PUBLIC,
--     anon ou authenticated), eliminando qualquer GUC manipulável por cliente.
--
-- PRE-REQUISITO OBRIGATORIO:
--   Execute após 01_CRIAR_TABELAS_DO_ZERO.sql e 05_FUNCOES_AUTORIZACAO.sql.
-- ============================================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS porttohub_internal;
REVOKE ALL ON SCHEMA porttohub_internal FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS porttohub_internal.passe_qr_tx_autorizacao (
  txid BIGINT PRIMARY KEY,
  passe_id UUID NOT NULL,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
REVOKE ALL ON TABLE porttohub_internal.passe_qr_tx_autorizacao FROM PUBLIC, anon, authenticated;

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
SET search_path = public, auth, porttohub_internal, pg_catalog
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

  -- 1. Sem auth.uid(), aceita EXCLUSIVAMENTE papel JWT comprovadamente service_role (zero bypass por current_user)
  IF auth.uid() IS NULL THEN
    IF v_jwt_role <> 'service_role' THEN
      RETURN jsonb_build_object(
        'valido', FALSE,
        'motivo', 'Autenticação obrigatória para validar ou consumir Passe Virtual.'
      );
    END IF;
    v_operador_nome := COALESCE(NULLIF(trim(p_operador_nome), ''), 'Sistema');
  ELSE
    -- 2. Para qualquer usuário autenticado, deriva o operador EXCLUSIVAMENTE por auth.uid() (ignora p_operador_nome do cliente)
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

  -- Lock exclusivo da linha (FOR UPDATE) impede consumo simultâneo acima de max_usos
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
    INSERT INTO porttohub_internal.passe_qr_tx_autorizacao (txid, passe_id, criado_em)
    VALUES (txid_current(), v_passe.id, NOW())
    ON CONFLICT (txid) DO UPDATE SET passe_id = EXCLUDED.passe_id, criado_em = EXCLUDED.criado_em;

    UPDATE public.passes_virtuais_qr
    SET status = 'expirado', updated_at = NOW()
    WHERE id = v_passe.id;

    DELETE FROM porttohub_internal.passe_qr_tx_autorizacao WHERE txid = txid_current();
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

  -- Valida janela de horário no fuso de Brasília
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
    -- Mantém fail-closed se formato de horário estiver inválido
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', 'Janela de horário configurada no passe é inválida.',
      'passe', to_jsonb(v_passe)
    );
  END;

  v_max_usos := GREATEST(1, COALESCE(v_passe.max_usos, v_passe.limite_usos, 1));
  v_usos_atuais := GREATEST(0, COALESCE(v_passe.usos_realizados, 0));

  IF v_usos_atuais >= v_max_usos THEN
    INSERT INTO porttohub_internal.passe_qr_tx_autorizacao (txid, passe_id, criado_em)
    VALUES (txid_current(), v_passe.id, NOW())
    ON CONFLICT (txid) DO UPDATE SET passe_id = EXCLUDED.passe_id, criado_em = EXCLUDED.criado_em;

    UPDATE public.passes_virtuais_qr
    SET status = 'utilizado', updated_at = NOW()
    WHERE id = v_passe.id;

    DELETE FROM porttohub_internal.passe_qr_tx_autorizacao WHERE txid = txid_current();
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

  INSERT INTO porttohub_internal.passe_qr_tx_autorizacao (txid, passe_id, criado_em)
  VALUES (txid_current(), v_passe.id, NOW())
  ON CONFLICT (txid) DO UPDATE SET passe_id = EXCLUDED.passe_id, criado_em = EXCLUDED.criado_em;

  UPDATE public.passes_virtuais_qr
  SET
    usos_realizados = v_novos_usos,
    status = v_novo_status,
    updated_at = NOW()
  WHERE id = v_passe.id
  RETURNING * INTO v_passe;

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

  DELETE FROM porttohub_internal.passe_qr_tx_autorizacao WHERE txid = txid_current();

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

COMMIT;

NOTIFY pgrst, 'reload schema';
