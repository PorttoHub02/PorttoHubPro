# PORTTOHUB PRO — Sistema de Gestão Operacional de Portaria Multi-Condomínio

Aplicação web/PWA multi-condomínio (multi-tenant) para operação de portaria, controle de encomendas, custódia, bancada de conferência, rondas patrimoniais, quadro de chaves, prestadores de serviço, livro de ocorrências, passagem de posto, reservas de áreas e controle de acesso.

- **Repositório oficial:** `https://github.com/PorttoHub02/PorttoHubPro` (branch `main`)
- **Frontend:** React 19 + TypeScript + Vite 8 + Tailwind CSS v4 + IndexedDB (`idb`) + PWA
- **Backend / Borda:** Express (`server.ts`) e Cloudflare Worker (`src/worker.ts` + Assets `./dist`) compartilhando manipuladores Web-Standard em `src/server/apiHandlers.ts`
- **Banco, Auth, Storage e Realtime:** Supabase (PostgreSQL + Supabase Auth + RLS + Storage privado + Realtime)
- **Cache REST:** Upstash Redis REST (`src/server/upstashClient.ts`) exclusivamente para aceleração de consultas de leitura com chaves isoladas por condomínio (`porttohub:v1:condo:<condominioId>:<table>:...`)

---

## 1. Arquitetura e Segurança

### 1.1 Autenticação e Passagem de Posto
- Autenticação exclusiva via **Supabase Auth** (`supabase.auth.signInWithPassword` e JWT validado no backend via `/auth/v1/user`).
- Nenhuma senha é armazenada ou consultada na tabela `public.operadores` nem em `localStorage`.
- Consultas a `public.operadores` utilizam projeções explícitas (`OPERADOR_SAFE_COLUMNS`), nunca `select('*')`.
- Na **Passagem de Posto** (`src/pages/PassagemPosto.tsx`) e **Assumir Posto de Ronda** (`src/pages/Rondas.tsx`), a reautenticação do operador entrante usa cliente Supabase efêmero (`persistSession: false` em `src/services/autorizacaoService.ts`), validando as credenciais reais no Supabase Auth sem sobrescrever a sessão ativa nem gravar sessão em `localStorage`.

### 1.2 Isolamento Multi-Tenant e Provisionamento
- **Frontend (`src/services/autorizacaoService.ts`)**: acesso global existe **somente** quando `acesso_global_condominios === true` no banco. Porteiros e síndicos permanecem restritos ao condomínio vinculado; supervisores acessam apenas os vínculos explícitos em `operador_condominios`.
- **Backend (`src/server/authMiddleware.ts` e `src/server/apiHandlers.ts`)**:
  - Todas as rotas `/api/*` protegidas exigem `Authorization: Bearer <jwt>` verificado diretamente no Supabase Auth.
  - `POST /api/admin/operadores/provisionar` valida no servidor a identidade real do solicitante, impede gestores locais de alterar contas de outros condomínios, contas globais (`acesso_global_condominios = true`) ou fornecer `auth_user_id` arbitrário sem vínculo de `operador_id`.
  - `SUPABASE_SERVICE_ROLE_KEY` nunca é exposta ao frontend nem retornada em respostas HTTP.
- **PostgreSQL RLS & Storage (`supabase/sql/`)**: políticas baseadas em `auth.uid()` e vínculos em `operadores` / `operador_condominios`, com Storage privado estritamente segregado no prefixo `condominios/{condominio_id}/...`.

### 1.3 Controle de Acesso, QR Code e Offline-First
- **Passes Virtuais QR (`src/services/passeQrValidation.ts`, `src/server/apiHandlers.ts`, `supabase/sql/05B_FUNCOES_PASSE_QR.sql`)**:
  - Tokens gerados com Web Crypto CSPRNG (`crypto.getRandomValues`, formato `PASS-XXXX-XXXX`).
  - Validação e consumo atômico via `POST /api/controle-acesso/validar-passe` e RPC PostgreSQL `validar_e_consumir_passe_qr` (`FOR UPDATE` + controle de fuso `America/Sao_Paulo` + limite `max_usos`).
  - Modo offline bloqueia validação/consumo de Passes QR para impedir reutilização indevida.
- **Sincronização Offline (`src/services/offlineSyncEngine.ts`, `src/services/porttoHubDb.ts`)**:
  - Fila persistente com `operation_id` idempotente, `condominio_id` e `operador_id` validados antes do replay no Supabase.
  - Operações com falha de rede são enfileiradas de forma explícita (`sincronizado: false`); erros de autorização/RLS retornam erro real ao operador.
- **Módulos em Demonstração Visual**:
  - `TotemValidator.tsx` e `FacialEnrollment.tsx` operam explicitamente em **Modo Demonstração / Simulador Visual**, sem motor biométrico facial real nem hardware IoT acoplado, e não gravam registros simulados no histórico real de acessos.

---

## 2. Variáveis de Ambiente

Veja `.env.example`. Nunca comite chaves reais ou tokens no repositório.

### Frontend (`VITE_*` — públicas no bundle)
- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`

### Servidor / Cloudflare Workers Secrets (privadas — somente backend)
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`
- `GEMINI_API_KEY` (opcional, para `/api/ocr-etiqueta`)
- `GEMINI_OCR_MODEL` (padrão `gemini-4-hydrogen`)
- `GITHUB_TOKEN` (opcional, leitura de versão em `/api/github-versao`)

> Em produção no Cloudflare Worker, `GET /env-config.js` injeta dinamicamente `VITE_SUPABASE_URL` e `VITE_SUPABASE_ANON_KEY` públicos no cliente, permitindo atualização via Worker secrets sem hardcode.

---

## 3. Migrações Supabase (`supabase/sql/`)

Execute no SQL Editor do projeto Supabase novo na ordem exata abaixo (scripts idempotentes e não destrutivos):

1. `00B_DIAGNOSTICO_DESTINO.sql` — Diagnóstico prévio do projeto destino
2. `01_CRIAR_TABELAS_DO_ZERO.sql` — Criação das tabelas operacionais (já sem coluna `senha` em `operadores`)
3. `02_PREPARAR_ESTRUTURA_OPERADORES.sql` — Colunas Auth/RBAC de operadores (compatibilidade legada não destrutiva)
4. `03_VINCULAR_OPERADORES_A_AUTH.sql` — Vínculo `operadores.auth_user_id` com `auth.users`
5. `04_VINCULOS_OPERADOR_CONDOMINIO.sql` — Tabela multi-vínculo `operador_condominios`
6. `05_FUNCOES_AUTORIZACAO.sql` — Funções `SECURITY DEFINER` de autorização (`operador_pode_acessar_condominio`, `operador_tem_acesso_global`, `operador_pode_gerenciar_operadores`, etc.)
7. `05B_FUNCOES_PASSE_QR.sql` — RPC transacional `validar_e_consumir_passe_qr` com `FOR UPDATE`
8. `06_RLS_TABELAS_MULTI_TENANT.sql` — Habilitação e políticas RLS por condomínio em todas as tabelas
9. `07_STORAGE_PRIVADO_POLICIES.sql` — Bucket privado `encomendas` e políticas estritas por prefixo `condominios/{condominio_id}/...`
10. `08_INDICES_E_CONSTRAINTS.sql` — Índices compostos por `condominio_id` e constraints de integridade (`ux_passes_qr_condo_token`, `chk_passes_qr_usos_limite`, etc.)
11. `09_VALIDACAO_SEGURANCA.sql` — Auditoria automatizada de RLS, funções, storage e tabelas
12. `10_ROLLBACK_OU_RECUPERACAO.sql` — Procedimentos de reversão segura sem `DROP TABLE`

---

## 4. Endpoints Backend (`/api/*`)

- `GET /api/health` — Saúde do servidor/Worker e status de configuração (sem segredos)
- `GET /api/github-versao` — Último commit do repositório `PorttoHub02/PorttoHubPro`
- `POST /api/ocr-etiqueta` — Extração OCR de etiquetas via Gemini no backend (requer JWT)
- `POST /api/admin/operadores/provisionar` — Criação/atualização de conta Supabase Auth com validação multi-tenant estrita (requer JWT de gestor autorizado)
- `POST /api/controle-acesso/validar-passe` — Validação e consumo atômico de Passe Virtual QR (requer JWT e acesso ao condomínio)
- `POST /api/cache/query`, `POST /api/cache/invalidate`, `GET /api/cache/stats`, `POST /api/cache/clear`, `POST /api/cache/warmup`, `GET /api/cache/benchmark` — Operações de cache Upstash Redis isoladas por tenant (requer JWT)

---

## 5. Scripts e Implantação (Cloudflare Workers)

```bash
npm install
npm run dev       # Servidor Express + Vite na porta 3000
npm test          # Suíte de testes de segurança, domínio e auditoria
npm run lint      # Verificação TypeScript (tsc --noEmit)
npm run build     # Build de produção em ./dist
npm run deploy    # Build + wrangler deploy para Cloudflare Workers (wrangler.jsonc)
```

Para configurar secrets no Cloudflare Worker:
```bash
npx wrangler secret put SUPABASE_URL
npx wrangler secret put SUPABASE_ANON_KEY
npx wrangler secret put SUPABASE_SERVICE_ROLE_KEY
npx wrangler secret put UPSTASH_REDIS_REST_URL
npx wrangler secret put UPSTASH_REDIS_REST_TOKEN
npx wrangler secret put VITE_SUPABASE_URL
npx wrangler secret put VITE_SUPABASE_ANON_KEY
npx wrangler secret put GEMINI_API_KEY
```
