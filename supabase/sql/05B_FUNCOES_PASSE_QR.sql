-- ============================================================================
-- PORTTOHUB PRO — 05B_FUNCOES_PASSE_QR.sql
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   Cria a função PostgreSQL transacional `public.validar_e_consumir_passe_qr`
--   para validar e consumir Passes Virtuais QR de forma atômica no banco,
--   impedindo corrida concorrente (race condition) de `max_usos`, reutilização
--   após limite, acesso fora da janela de data/horário ou vazamento entre
--   condomínios.
--
-- PRE-REQUISITO OBRIGATORIO:
--   Execute após 01_CRIAR_TABELAS_DO_ZERO.sql e 05_FUNCOES_AUTORIZACAO.sql.
-- ============================================================================

BEGIN;

CREATE OR REPLACE FUNCTION public.validar_e_consumir_passe_qr(
  p_condominio_id UUID,
  p_token TEXT,
  p_consumir BOOLEAN DEFAULT FALSE,
  p_ponto_acesso TEXT DEFAULT 'Portaria Principal (Pedestres)',
  p_operador_nome TEXT DEFAULT 'Portaria'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  v_passe RECORD;
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
  IF p_condominio_id IS NULL OR NOT public.operador_pode_acessar_condominio(p_condominio_id::text) THEN
    RETURN jsonb_build_object(
      'valido', FALSE,
      'motivo', 'Acesso negado: operador não autorizado para este condomínio.'
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
    UPDATE public.passes_virtuais_qr
    SET status = 'expirado', updated_at = NOW()
    WHERE id = v_passe.id;
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
    UPDATE public.passes_virtuais_qr
    SET status = 'utilizado', updated_at = NOW()
    WHERE id = v_passe.id;
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
    COALESCE(NULLIF(trim(p_operador_nome), ''), 'Portaria'),
    format('Liberado via Passe QR (%s) [Uso %s/%s] - %s', v_passe.token, v_novos_usos, v_max_usos, COALESCE(v_passe.observacoes, '')),
    v_passe.id
  )
  RETURNING id INTO v_registro_id;

  RETURN jsonb_build_object(
    'valido', TRUE,
    'consumido', TRUE,
    'registro_id', v_registro_id,
    'passe', to_jsonb(v_passe)
  );
END;
$$;

REVOKE ALL ON FUNCTION public.validar_e_consumir_passe_qr(UUID, TEXT, BOOLEAN, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.validar_e_consumir_passe_qr(UUID, TEXT, BOOLEAN, TEXT, TEXT) TO authenticated, service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
