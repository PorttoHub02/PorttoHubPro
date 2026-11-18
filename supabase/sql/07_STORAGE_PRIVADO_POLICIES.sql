-- ============================================================================
-- PORTTOHUB PRO — 07_STORAGE_PRIVADO_POLICIES.sql
-- ============================================================================
-- O QUE ESTE ARQUIVO FAZ:
--   1. Torna o bucket 'encomendas' PRIVADO (public = FALSE) no Supabase Storage,
--      impedindo que fotos de pacotes, moradores e visitantes sejam acessíveis
--      por links públicos abertos na internet.
--   2. Remove políticas antigas TO public e exige usuário autenticado + acesso
--      ao condomínio dono da pasta (condominios/{condominio_id}/...).
--
-- QUANDO EXECUTAR (SEQUÊNCIA ÚNICA OFICIAL):
--   - Em banco NOVO / implantação inicial: execute normalmente na ordem oficial,
--     logo após 06_RLS_TABELAS_MULTI_TENANT.sql e antes de 08 e 09, garantindo
--     que o Storage já nasça 100% privado antes da publicação no Cloudflare.
--   - Em atualização de sistema legado em produção: certifique-se de que o
--     frontend publicado já utiliza URLs assinadas e prefixo
--     condominios/{condominio_id}/... antes de aplicar este bloqueio.
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

-- 2. Remove políticas públicas antigas do bucket 'encomendas'
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
--    Formato obrigatório para módulos condominiais: condominios/<condominio_id>/<modulo>/<arquivo>
CREATE POLICY "porttohub_storage_select"
  ON storage.objects
  FOR SELECT
  TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND (storage.foldername(name))[1] = 'condominios'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

CREATE POLICY "porttohub_storage_insert"
  ON storage.objects
  FOR INSERT
  TO authenticated
  WITH CHECK (
    bucket_id = 'encomendas'
    AND (storage.foldername(name))[1] = 'condominios'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

CREATE POLICY "porttohub_storage_update"
  ON storage.objects
  FOR UPDATE
  TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND (storage.foldername(name))[1] = 'condominios'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  )
  WITH CHECK (
    bucket_id = 'encomendas'
    AND (storage.foldername(name))[1] = 'condominios'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

CREATE POLICY "porttohub_storage_delete"
  ON storage.objects
  FOR DELETE
  TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND (storage.foldername(name))[1] = 'condominios'
    AND public.operador_pode_acessar_condominio((storage.foldername(name))[2])
  );

-- 4. Políticas privadas de foto de perfil do próprio operador autenticado:
--    Formato seguro sem vínculo condominial obrigatório: operadores/<auth.uid()>/<arquivo>
--    Atende inclusive admin_geral sem condomínio ativo, sem conceder acesso a outros condomínios.
CREATE POLICY "porttohub_storage_operadores_select"
  ON storage.objects
  FOR SELECT
  TO authenticated
  USING (
    bucket_id = 'encomendas'
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
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

CREATE POLICY "porttohub_storage_operadores_update"
  ON storage.objects
  FOR UPDATE
  TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  )
  WITH CHECK (
    bucket_id = 'encomendas'
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

CREATE POLICY "porttohub_storage_operadores_delete"
  ON storage.objects
  FOR DELETE
  TO authenticated
  USING (
    bucket_id = 'encomendas'
    AND (storage.foldername(name))[1] = 'operadores'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

COMMIT;
