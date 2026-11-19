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
- **PostgreSQL RLS, Autoria & Storage (`supabase/sql/`)**:
  - Políticas granulares baseadas em `auth.uid()` e vínculos em `operadores` / `operador_condominios`, com Storage privado estritamente segregado nos prefixos `condominios/{condominio_id}/...` e `operadores/{auth.uid()}/...`.
  - **Fonte única de permissões personalizadas**: `public.operador_tem_permissao_modulo()` no PostgreSQL, `src/server/authMiddleware.ts` no backend e `src/services/permissoesService.ts` no frontend consultam a matriz `configuracoes.niveis_acesso` do condomínio alvo (com `operadores.permissoes` como camada de override e falha fechada para `nivel_acesso_custom_id` ausente).
  - **Escopo estrito às 35 tabelas oficiais e preservação de tabelas extras**: Os scripts `06_RLS_TABELAS_MULTI_TENANT.sql` e `11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql` aplicam revogação de privilégios, `GRANT`s, políticas RLS e ajuste de sequências (`pg_depend`) **exclusivamente** sobre a lista canônica das 35 tabelas oficiais do PorttoHub Pro. Caso existam tabelas ou sequências extras no schema `public`, a pré-auditoria as reporta claramente via `RAISE NOTICE` e **preserva integralmente** seus privilégios, políticas e configurações sem alterações silenciosas.
  - **Proteção de autoria (`historico_absoluto` e `registros_acesso`)**: Triggers `SECURITY INVOKER` gravam automaticamente `operador_id` (e `operador_nome` / `operador_login` / `operador_registro` no caso de auditoria e acessos normais) a partir de `auth.uid()`, impedindo falsificação de identidade pelo cliente (com exceção controlada apenas para `service_role`, SQL Editor administrativo e consumo transacional de Passe QR).

### 1.3 Controle de Acesso, QR Code e Offline-First
- **Passes Virtuais QR (`src/services/passeQrValidation.ts`, `src/server/apiHandlers.ts`, `supabase/sql/05B_FUNCOES_PASSE_QR.sql`)**:
  - Tokens gerados com Web Crypto CSPRNG (`crypto.getRandomValues`, formato `PASS-XXXX-XXXX`).
  - Validação e consumo atômico via `POST /api/controle-acesso/validar-passe` e RPC PostgreSQL `validar_e_consumir_passe_qr` (`FOR UPDATE` + controle de fuso `America/Sao_Paulo` + limite `max_usos`).
  - Autorização via marcador transacional interno em `porttohub_internal.passe_qr_tx_autorizacao` (schema privado inacessível a `PUBLIC`, `anon` e `authenticated`, em substituição ao antigo GUC de sessão), somado a trigger bloqueando alteração direta de campos protegidos em `passes_virtuais_qr`.
  - Modo offline bloqueia validação/consumo de Passes QR para impedir reutilização indevida.
- **Sincronização Offline (`src/services/offlineSyncEngine.ts`, `src/services/porttoHubDb.ts`)**:
  - Fila persistente com `operation_id` idempotente, `condominio_id` e `operador_id` validados antes do replay no Supabase.
  - Operações com falha de rede são enfileiradas de forma explícita (`sincronizado: false`); erros de autorização/RLS retornam erro real ao operador.
- **Módulos em Demonstração Visual**:
  - `TotemValidator.tsx` e `FacialEnrollment.tsx` operam explicitamente em **Modo Demonstração / Simulador Visual**, sem motor biométrico facial real nem hardware IoT acoplado, e não gravam registros simulados no histórico real de acessos.

---

## 2. Variáveis de Ambiente e Método Oficial de Configuração

Veja `.env.example`. Nunca comite chaves reais ou tokens no repositório.

### Método Oficial Único no Cloudflare Worker (`porttohubpro`)
O Worker possui o endpoint dinâmico `GET /env-config.js`, que lê as variáveis de ambiente do próprio Worker e as entrega ao navegador antes do carregamento da aplicação React. Portanto, **não é necessário duplicar variáveis de build e runtime**:

#### Variáveis Públicas (cadastrar como **Text / Plaintext** em *Variables and Secrets*)
- `SUPABASE_URL` — URL do projeto Supabase (ex.: `https://npqcrifwkfovrrsnktyb.supabase.co`)
- `SUPABASE_PUBLISHABLE_KEY` (prioritária) ou `SUPABASE_ANON_KEY` — Chave pública do projeto Supabase

> *(Opcional em builds locais com `.env`: `VITE_SUPABASE_URL` e `VITE_SUPABASE_ANON_KEY`. Em produção no Cloudflare Worker, `SUPABASE_URL` + `SUPABASE_PUBLISHABLE_KEY` / `SUPABASE_ANON_KEY` alimentam tanto o backend `/api/*` quanto o frontend via `/env-config.js`, preservados automaticamente por `keep_vars: true` no `wrangler.jsonc`.)*

#### Secrets Privados (cadastrar como **Secret / Encrypted** em *Variables and Secrets*)
- `SUPABASE_SERVICE_ROLE_KEY` — Chave administrativa server-only (obrigatória para provisionamento de operadores; nunca exposta ao navegador)
- `UPSTASH_REDIS_REST_URL` — Endpoint REST do Upstash Redis
- `UPSTASH_REDIS_REST_TOKEN` — Token REST do Upstash Redis
- `GEMINI_API_KEY` — *(opcional)* Chave Gemini para `/api/ocr-etiqueta`
- `GITHUB_TOKEN` — *(opcional)* Token read-only para `/api/github-versao`

---

## 3. Sequência Oficial Completa das Migrações Supabase (`supabase/sql/`)

Execute no **SQL Editor** do projeto Supabase novo na ordem exata abaixo (todos os scripts são idempotentes e não destrutivos):

1. `00B_DIAGNOSTICO_DESTINO.sql` — Diagnóstico somente leitura (seguro mesmo em banco 100% vazio)
2. `01_CRIAR_TABELAS_DO_ZERO.sql` — Criação das 35 tabelas operacionais (já sem coluna `senha` em `operadores`)
3. `02_PREPARAR_ESTRUTURA_OPERADORES.sql` — Colunas Auth/RBAC e índices únicos de operadores
4. **PASSO MANUAL NO PAINEL AUTH (obrigatório antes do script 03):**
   - Acesse **Authentication -> Users -> Add user -> Create new user**
   - Informe o e-mail e senha forte do 1º Administrador Geral e mantenha **Auto Confirm User** marcado
5. `03_VINCULAR_OPERADORES_A_AUTH.sql` — Edite os 3 campos (`v_email_admin`, `v_nome_admin`, `v_nome_condominio`) e execute para criar o 1º condomínio e vincular o Administrador Geral
6. `04_VINCULOS_OPERADOR_CONDOMINIO.sql` — Tabela oficial multi-vínculo `operador_condominios`
7. `05_FUNCOES_AUTORIZACAO.sql` — Funções `SECURITY DEFINER` de autorização (`operador_pode_acessar_condominio`, `operador_tem_acesso_global`, `operador_pode_gerenciar_operadores`, `operador_tem_permissao_modulo` unificada com `configuracoes.niveis_acesso`, etc.)
8. `05B_FUNCOES_PASSE_QR.sql` — Schema privado `porttohub_internal.passe_qr_tx_autorizacao` e RPC transacional `validar_e_consumir_passe_qr` com `FOR UPDATE`
9. `06_RLS_TABELAS_MULTI_TENANT.sql` — Revogação/grants/RLS estritamente nas 35 tabelas oficiais e sequências vinculadas (preservando eventuais tabelas extras intactas), além de triggers de autoria e proteção de Passe QR
10. `07_STORAGE_PRIVADO_POLICIES.sql` — Bucket privado `encomendas` e 8 políticas estritas (`condominios/{condominio_id}/...` e `operadores/{auth.uid()}/...`)
11. `08_INDICES_E_CONSTRAINTS.sql` — Índices compostos por `condominio_id`, constraints de integridade e validação automática de `chk_passes_qr_usos_limite`
12. `09_VALIDACAO_SEGURANCA.sql` — Auditoria automatizada (deve exibir `OK` nos 10 itens do resumo)

### Atualização Incremental em Banco Já Implantado (Sem Reset)
Se o projeto Supabase já possui tabelas, Admin Geral e registros operacionais em produção:
1. Execute `11_CORRECOES_SEGURANCA_E_ALINHAMENTO.sql` — Migração idempotente e não destrutiva atuando **exclusivamente nas 35 tabelas oficiais** e suas sequências vinculadas (`pg_depend`), preservando qualquer tabela extra existente no schema `public`. Aplica `SECURITY INVOKER` na trigger de operadores e nas triggers de autoria (`historico_absoluto`, `registros_acesso`), unificação de `configuracoes.niveis_acesso`, proteção da coluna `permissoes`, marcador transacional `porttohub_internal.passe_qr_tx_autorizacao`, revogação de `anon`/`PUBLIC`/`TRUNCATE`, políticas granulares nas 35 tabelas, 8 políticas de Storage e `VALIDATE CONSTRAINT` segura.
2. Execute `12_AUDITORIA_FINAL_SEGURANCA.sql` — Auditoria final 100% somente leitura (4 quadros) com status padronizados (`OK`, `ATENÇÃO`, `FALHA` e `NÃO TESTADO`). As checagens de corpo de função são marcadas explicitamente como `VERIFICAÇÃO ESTRUTURAL`, e testes dinâmicos de `/api/*` ou integração multi-tenant real ficam em `NÃO TESTADO` para execução via `npm run test:integration`.

> **ATENÇÃO — NÃO EXECUTAR NA INSTALAÇÃO NORMAL:**
> O arquivo `10_ROLLBACK_OU_RECUPERACAO.sql` é uma ferramenta manual de **contingência/emergência** (uso exclusivo de suporte caso um operador específico perca vínculo posteriormente). **NÃO execute `10_ROLLBACK_OU_RECUPERACAO.sql` durante a instalação normal.**

---

## 4. Endpoints Backend (`/api/*`)

- `GET /env-config.js` — Injeta configuração pública do Supabase (`VITE_SUPABASE_URL` e `VITE_SUPABASE_ANON_KEY`) no cliente em runtime
- `GET /api/health` — Saúde do servidor/Worker e status de configuração (sem segredos)
- `GET /api/github-versao` — Último commit do repositório `PorttoHub02/PorttoHubPro`
- `POST /api/ocr-etiqueta` — Extração OCR de etiquetas via Gemini no backend (requer JWT)
- `POST /api/admin/operadores/provisionar` — Criação/atualização de conta Supabase Auth com validação multi-tenant estrita (requer JWT de gestor autorizado)
- `POST /api/controle-acesso/validar-passe` — Validação e consumo atômico de Passe Virtual QR (requer JWT e acesso ao condomínio)
- `POST /api/cache/query`, `POST /api/cache/invalidate`, `GET /api/cache/stats`, `POST /api/cache/clear`, `POST /api/cache/warmup`, `GET /api/cache/benchmark` — Operações de cache Upstash Redis isoladas por tenant (requer JWT)

---

## 5. Scripts e Implantação (Cloudflare Worker `porttohubpro`)

O arquivo `wrangler.jsonc` aponta diretamente para `"name": "porttohubpro"`, reutilizando o Worker já existente na conta Cloudflare sem criar serviços duplicados.

```bash
npm install
npm run dev              # Servidor Express + Vite na porta 3000
npm test                 # Suíte unitária/mock de segurança, domínio e auditoria
npm run test:integration # Testes reais contra Supabase (requer variáveis SUPABASE_TEST_*)
npm run lint             # Verificação TypeScript (tsc --noEmit)
npm run build            # Build de produção em ./dist
npm run deploy           # Build + wrangler deploy no Worker existente (porttohubpro)
```

Para configurar secrets via CLI no Worker `porttohubpro` (ou cadastre pelo painel Cloudflare em *Workers & Pages -> porttohubpro -> Settings -> Variables and Secrets*):
```bash
npx wrangler secret put SUPABASE_SERVICE_ROLE_KEY
npx wrangler secret put UPSTASH_REDIS_REST_URL
npx wrangler secret put UPSTASH_REDIS_REST_TOKEN
npx wrangler secret put GEMINI_API_KEY
```
