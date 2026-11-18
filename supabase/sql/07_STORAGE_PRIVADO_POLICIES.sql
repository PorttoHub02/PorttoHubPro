-- ============================================================================
-- PORTTOHUB PRO — 07_STORAGE_PRIVADO_POLICIES.sql
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   1. Torna o bucket 'encomendas' PRIVADO (public = FALSE) no Supabase Storage,
--      impedindo que fotos de pacotes, moradores, visitantes e avatares sejam
--      acessíveis por links públicos abertos na internet.
--   2. Remove políticas antigas TO public e exige usuário autenticado e ativo,
--      garantindo as 8 políticas privadas oficiais:
--        - 4 CRUD em `condominios/{condominio_id}/...` (com UUID válido)
--        - 4 CRUD em `operadores/{auth.uid()}/...` (escopo próprio autenticado)
--
-- QUANDO EXECUTAR (SEQUÊNCIA ÚNICA OFICIAL):
--   - Em banco NOVO / implantação inicial: execute na ordem oficial logo após
--     06_RLS_TABELAS_MULTI_TENANT.sql e antes de 08 e 09.
--   - Em atualização de produção: execute após garantir que o app usa URLs
--     assinadas (createSignedUrl) e os prefixos oficiais.
-- ============================================================================

BEGIN;

-- 1. Configura o bucket 'encomendas' como PRIVADO com limite de 10 MB e MIME restrito
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

-- 2. Remove políticas públicas antigas e recria políticas oficiais do bucket 'encomendas'
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

-- 3. Políticas privadas isoladas por condominio_id no prefixo do path:
--    Formato obrigatório para módulos condominiais: condominios/<condominio_uuid>/<modulo>/<arquivo>
CREATE POLICY "porttohub_storage_select"
  ON storage.objects
  FOR SELECT
  TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'condominios'
    AND (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

CREATE POLICY "porttohub_storage_insert"
  ON storage.objects
  FOR INSERT
  TO authenticated
  WITH CHECK (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'condominios'
    AND (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

CREATE POLICY "porttohub_storage_update"
  ON storage.objects
  FOR UPDATE
  TO authenticated
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
  ON storage.objects
  FOR DELETE
  TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'condominios'
    AND (storage.foldername(name))[2] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

-- 4. Políticas privadas de foto de perfil do próprio operador ativo autenticado:
--    Formato seguro sem vínculo condominial obrigatório: operadores/<auth.uid()>/<arquivo>
CREATE POLICY "porttohub_storage_operadores_select"
  ON storage.objects
  FOR SELECT
  TO authenticated
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
  ON storage.objects
  FOR INSERT
  TO authenticated
  WITH CHECK (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

CREATE POLICY "porttohub_storage_operadores_update"
  ON storage.objects
  FOR UPDATE
  TO authenticated
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
  ON storage.objects
  FOR DELETE
  TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND auth.uid() IS NOT NULL
    AND public.operador_atual_id() IS NOT NULL
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

COMMIT;
