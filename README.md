<div align="center">

# 🛡️ SOC Detection Copilot

**A practical SOC Analyst / Detection Engineer workspace.**
Take raw logs exported from Elastic — or uploaded/pasted from anywhere — and run them through a real, end-to-end detection engineering workflow: field discovery, ECS mapping, behavioral detection, MITRE ATT&CK mapping, rule generation, testing, false-positive analysis, and tuning.

![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![Tests](https://img.shields.io/badge/tests-357%20passing-brightgreen)
![No build step](https://img.shields.io/badge/frontend-vanilla%20JS%2C%20no%20build%20step-blue)
![Deterministic core](https://img.shields.io/badge/core%20logic-deterministic-informational)
![Status](https://img.shields.io/badge/status-active-success)

</div>

---

This is **not** a generic "paste logs, get an AI answer" tool. Every calculation that can be deterministic *is* deterministic — parsing, ECS confidence scoring, detection thresholds, MITRE mapping, rule syntax validation, statistics. An LLM is only ever used, optionally, for supplementary narrative text, and every one of those code paths has a deterministic fallback.

## Table of contents

- [The pipeline](#the-pipeline)
- [Features](#features)
- [Quick start](#quick-start)
- [Deploy online](#deploy-online)
- [Running tests](#running-tests)
- [Project layout](#project-layout)
- [Environment variables](#environment-variables)
- [API](#api)
- [Security](#security)
- [Known limitations](#known-limitations-stated-honestly-not-hidden)
- [MATURITY.md](MATURITY.md) — a deterministic, fact-checked production-readiness assessment (test counts, security controls, and explicit scope boundaries, each tied to a re-runnable command or file reference)

## The pipeline

```mermaid
flowchart LR
    A[Raw Logs] --> B[Parsing]
    B --> C[Field Discovery]
    C --> D[ECS Mapping]
    D --> E[Normalization]
    E --> F[Detection Engineering]
    F --> G[MITRE ATT&CK Mapping]
    G --> H[Rule Generation]
    H --> I[Rule Validation]
    I --> J[Rule Testing]
    J --> K[False Positive Analysis]
    K --> L[Tuning]
    L --> M[✅ Production-Ready Detection]

    style A fill:#0f1520,stroke:#2dd4bf,color:#e6edf3
    style M fill:#164e47,stroke:#2dd4bf,color:#e6edf3
```

| Stage | What happens |
|---|---|
| **Parsing** | Format detection (JSON / NDJSON / CSV / plain-text), safe bounded parsing — no `eval` |
| **Field Discovery** | Types, frequency, null %, security relevance for every field in the dataset |
| **ECS Mapping** | Deterministic, confidence-scored field → ECS suggestions, fully analyst-editable |
| **Normalization** | Raw event → normalized ECS event, with a side-by-side diff |
| **Detection Engineering** | Auth / Linux / Windows / network / web / firewall behavior analysis |
| **MITRE ATT&CK Mapping** | Static, explainable lookup — uncertainty is always flagged, never hidden |
| **Rule Generation** | KQL / ES\|QL / EQL / Lucene / Sigma, built from the detection's own match logic |
| **Rule Validation** | Syntax + logic checked (contradictory/impossible conditions, non-ECS fields, leading wildcards, bare match-all) — errors vs warnings kept separate, never executed against a live system |
| **Rule Testing** | Run against your own loaded logs for real match counts |
| **False Positive Analysis** | Potential FPs cross-checked against the detection's own evidence, broken down by top recurring field/value pairs and common dimensions (users, hosts, processes, destinations), with data-driven exclusion suggestions - never applied automatically |
| **Tuning** | Threshold recommendation with a real before/after re-test, including the false-positive rate at the new threshold (not just match count) - and a check that the suggested threshold doesn't just "fix" the rate by matching nothing |
| **Report** | Exportable JSON / Markdown / CSV Detection Engineering Report |

## Features

- 🗂️ **Multi-source ingestion** — file upload, paste, 8 bundled sample datasets, or a direct Elasticsearch fetch (all optional, all env-configured)
- 🔍 **Log source identification** — Linux SSH, Windows Security, Sysmon, Apache/Nginx/IIS, firewalls (Fortinet/Palo Alto/Cisco/generic), DNS, DHCP, VPN, proxy, EDR, cloud (CloudTrail/Azure/M365), database, and custom application logs. Shows every candidate that was considered, not just the winner - uncertainty is never hidden behind a single confident-looking answer
- 🧭 **Analyst-in-the-loop ECS mapping** — every suggestion shows its confidence and reasoning, and can be overridden before normalization. Six meaningful statuses, not just "mapped/unmapped": `confident`, `uncertain`, `custom` (a real application field - not an ECS gap), `unsupported` (array/object value, needs manual transformation), `excluded` (Elasticsearch's own metadata), `unmapped` (a genuine schema gap under a real ECS namespace) - and mapping coverage % is never penalized by an analyst's own custom fields
- 🕵️ **6 behavior families, 25+ individual detections** — brute force, password spraying, privileged auth, reverse shells, suspicious sudo, encoded/suspicious PowerShell, LOLBins, credential dumping, persistence (services/scheduled tasks/registry run keys/cron), port scanning, DNS tunneling, C2 beaconing, SQLi/XSS/path traversal/web shells, and firewall anomalies
- 🧮 **Real deterministic evaluators** for the three hardest signals — CIDR internal/external direction (IPv4+IPv6, configurable ranges), DNS-tunneling entropy/length/character-distribution, and C2 beaconing timing regularity — each returns structured, explainable evidence (`detection-engine/evaluators/`), no LLM involved
- 🗳️ **Real detection lifecycle** — draft → generated → validated → tested → tuned → approved → production → deprecated, persisted to SQLite so a decision survives a restart, with an enforced guard (e.g. you cannot approve a detection that's never been tested) and a full audit trail per detection
- 🎯 **MITRE ATT&CK mapping** that never overstates confidence
- 📝 **5 query languages** generated per detection: KQL, ES\|QL, EQL, Lucene, Sigma
- ✅ **Real rule testing** — each detection carries the exact structured conditions that reproduced its own match, so "test against sample logs" reflects reality instead of a generic placeholder
- 🔎 **Errors vs. warnings in rule validation** — contradictory/impossible conditions (e.g. one field required to equal two different values at once) are hard errors; non-ECS fields, leading wildcards, and bare match-all queries are warnings, not blockers. Every generated query also carries `generatedAt` and the `detectionVersion` it was built from, so a query can never be silently mistaken for a different revision of the same detection
- 🧪 **Positive/negative/edge test-case framework** — every rule gets an auto-generated set of test cases (seeded from a real matched event when one exists) plus PASS/FAIL/ERROR/SKIPPED per case and a real confusion matrix (precision/recall/F1/detection-rate/FP-rate, `null` rather than faked when a denominator is zero); analysts can add their own cases on top
- 📉 **Evidence-based false-positive breakdown & verified tuning** — potential FPs are ranked by which field/value pairs (and users/hosts/processes/destinations) actually recur among them, with "consider excluding X" suggestions computed from real counts, never applied automatically. Tuning re-verifies the false-positive rate *and* that true positives survive at the suggested threshold - raising a threshold high enough to match nothing is never reported as an improvement
- 📊 **SOC-style dashboard** — logs processed, mapping coverage, detections, rules validated, MITRE technique count, high-risk findings
- 🌓 **Dark SOC/SIEM-themed UI** — 13 tabs, no build step, no framework
- ✨ **Multi-provider AI assist, hardened** — Claude, Groq, OpenAI, or any other OpenAI-compatible API; configure via environment variables or paste a key straight into the **Settings** tab (session-memory only, never written to disk, always masked when shown back). Every call has a request timeout and a bounded retry policy with backoff for transient failures (network error, 429 rate limit, 5xx) - auth errors are never retried, and every failure carries a stable error code (`timeout`/`network`/`rate_limited`/`auth`/`server_error`), not just a message. Powers optional "Explain with AI" buttons on detections, ECS mappings, and false-positive analysis — every one of them has a deterministic fallback when no key is set or a call fails, and AI output is narrative-only: it can never alter a detection's severity/confidence/MITRE mapping, an ECS mapping, a rule's conditions/query, a test result, or a persisted lifecycle status
- 🔒 **Security-first**: upload allowlisting/size limits, bounded JSON parsing, catastrophic-backtracking-safe regexes, escaped/validated (never executed) query generation, rate limiting, env-var-only secrets, prototype-pollution guards on every analyst-editable field path, SSRF blocking on the custom AI endpoint, and a hard timeout on every outbound network call (AI provider, Elasticsearch)
- 🔑 **Opt-in authentication** — set one env var (`APP_PASSWORD`) to require a login for every API route and, functionally, the whole UI. A signed, `HttpOnly` session cookie, constant-time password comparison, never echoed back. Unset by default for zero-config local use, with a clear startup warning either way

## Quick start

```bash
cd backend
npm install
cp .env.example .env      # optional - the app works with no configuration
npm start                 # -> http://localhost:4000
```

Open `http://localhost:4000`, go to **Log Ingestion**, and click one of the **sample dataset** chips (SSH, Windows Security, Sysmon, Apache, Nginx, Firewall, DNS, generic Authentication) to run the full pipeline without needing an Elastic cluster.

To use your own data: upload a `.json` / `.jsonl` / `.ndjson` / `.txt` / `.log` / `.csv` file, or paste raw events directly. The app does **not** assume your logs are already ECS-compliant, and understands common Elastic export shapes (`message`, `event.original`, `log.original`).

## Deploy online

The app is a single Node/Express process. Session/pipeline data (parsed events, mappings, detections) is in-memory only, 2-hour TTL. The detection *lifecycle* (draft → ... → production) is persisted to a small SQLite file so an approval decision survives a restart - but on Render's free tier, the filesystem itself is ephemeral across deploys/restarts, same caveat as the in-memory session data (see [Environment variables](#environment-variables) for `DETECTION_DB_PATH` if you want it on a mounted persistent disk instead). It still deploys to any host that can run `node backend/src/server.js` and keep it alive. [Render](https://render.com) is the easiest free option:

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/hamzakhan947075/soc-detection-copilot)

1. Click the button above (or **New +** → **Blueprint** on Render and point it at this repo) — it reads [`render.yaml`](render.yaml), which builds/starts from `backend/`.
2. Wait for the first deploy to finish, then open the `.onrender.com` URL Render gives you.
3. Nothing else is required — every environment variable is optional. If you want AI-assist or a live Elasticsearch connection in the deployed app, either add them as environment variables in the Render dashboard (see the table below), or just open the deployed app's **Settings** tab and paste an API key in directly (session-memory only, never written to disk).

**Set `APP_PASSWORD` before sharing the URL with anyone, or leaving it publicly reachable.** Without it, anyone who finds the URL has full read/write access - there's no login at all, and the app logs a startup warning saying so. With `APP_PASSWORD` set, every API route (and functionally the whole UI) requires that password to do anything; see [Environment variables](#environment-variables).

Free-tier note: Render's free web services spin down after 15 minutes of inactivity and cold-start on the next request (session data does not survive a spin-down/restart, same as restarting it locally).

Any other Node host works the same way (Railway, Fly.io, a plain VPS with `pm2`/`systemd`, etc.) — just set the working directory to `backend/`, run `npm install && npm start`, and make sure the platform's assigned `PORT` reaches the process (the app already reads `process.env.PORT`).

## Running tests

```bash
cd backend
npm test              # 313 tests across parsing, field discovery, ECS
                       # mapping, detection engine, MITRE mapping, rule
                       # generation/validation, rule testing, false-positive
                       # analysis, tuning, AI provider config, API/upload
                       # security, auth, and structured request logging
npm run lint          # ESLint (backend/src, backend/tests, frontend/js);
                       # config lives at the repo root (eslint.config.js)
                       # since it covers both directories
```

Both run in CI (`.github/workflows/ci.yml`) on every push/PR, on Node 18.x
and 20.x, alongside a `npm audit --audit-level=high` dependency check, a
smoke test that actually boots the server and hits `/health`/`/ready`, and
the `e2e/` Playwright suite below in a real headless Chromium.

```bash
cd frontend
npm test              # 38 tests (Node's built-in test runner + jsdom, no
                       # bundler) covering utils.js, state.js's resolveStage,
                       # api.js's error-handling contract, and pipelineBar.js
```

```bash
cd e2e
npm install && npx playwright install --with-deps chromium   # one-time
npm test               # 6 tests, real Chromium against two real backend
                        # instances (playwright.config.js starts/stops them) -
                        # the full pipeline golden path (sample dataset through
                        # a rule to an exported report), the opt-in-auth
                        # login/logout flow, and a couple of frontend error
                        # paths, all driven exactly as a person would click.
```

## Project layout

```
backend/
  src/
    config/            environment variable loading (no hardcoded secrets)
    ingestion/         LogSource abstraction, upload validation, Elasticsearch client
    parsing/           format detection, safe JSON parsing, NDJSON/CSV/plain parsers
    field-discovery/   flattening, value-type inference, per-field statistics
    ecs-mapping/       ECS schema subset, alias dictionary, confidence-scored mapper
    log-source-id/     declarative log-source signatures + scorer
    normalization/     raw event -> normalized ECS event
    detection-engine/  behaviors/{auth,linux,windows,network,web,firewall}.js,
                       evaluators/{cidr,dnsTunneling,c2Beaconing}Evaluator.js
    detections/        canonical Detection record + lifecycle state machine (draft..production)
    persistence/       SQLite-backed detection lifecycle store (db.js, detectionStore.js)
    mitre/             static hint -> {tactic, technique} lookup
    rule-generation/   KQL/ES|QL/EQL/Lucene/Sigma builders + rule assembly
    rule-validation/   non-executing syntax validation
    testing/           executes a rule's structured conditions against events,
                       plus a labeled positive/negative/edge test-case
                       runner + generator (precision/recall/F1)
    false-positive/    dynamic FP analysis + static FP guidance
    tuning/             threshold tuning recommendation
    investigation/     per-category investigation checklists
    reporting/          Detection Engineering Report + dashboard aggregation
    ai/                 multi-provider (Claude/Groq/OpenAI/custom) narrative assist
    auth/               opt-in single-password session auth (session.js, authMiddleware.js)
    security/          helmet, rate limiting, safe error handler
    observability/      structured JSON-line request logging (metadata only)
    pipeline/          session store + orchestration + pipeline stage metadata
    routes/            Express API
  sample-data/         8 bundled sample datasets
  tests/               313 tests (see above)
  scripts/lint.js       runs ESLint via its Node API against the repo root
                       config, so `npm run lint` works whether invoked from
                       backend/ or CI
eslint.config.js        shared ESLint flat config for backend + frontend
.github/workflows/       CI: lint, test (Node 18.x/20.x), npm audit, boot smoke test
frontend/
  js/
    api.js, state.js, controller.js, pipelineBar.js, utils.js
    tabs/              13 tab modules: Overview, Log Ingestion, Field
                       Discovery, ECS Mapping, Detection Engineering, MITRE
                       ATT&CK, Rule Builder, Rule Testing, False Positive
                       Analysis, Detection Tuning, Investigation, Reports,
                       Settings
  tests/                 38 unit tests for the pure/testable frontend layer (Node's built-in test runner + jsdom)
  index.html, styles.css   dark SOC/SIEM-styled UI, no build step
e2e/                    6 real-browser end-to-end tests (Playwright + Chromium):
                        golden path, opt-in-auth login/logout, frontend error paths
ARCHITECTURE.md         data flow, design rationale, security posture
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full data-flow diagram and design rationale (in particular, why rule generation is keyed off a per-detection `ruleConditions` field rather than a generic lookup table).

## Environment variables

All optional — copy `backend/.env.example` to `backend/.env`. Nothing here is required to run the full pipeline against uploaded/pasted/sample data.

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port (default `4000`) |
| `NODE_ENV` | `production` restricts CORS to same-origin and marks the session cookie `Secure` (requires HTTPS); anything else (including unset) allows any origin and omits `Secure`, for local development |
| `APP_PASSWORD` | If set, every API route requires this password (session cookie, 12h TTL) - **unset means no login at all**, logged as a startup warning. See [Security](#security) |
| `SESSION_SECRET` | Signs the session cookie; auto-generated per boot if unset (sessions then don't survive a restart) |
| `MAX_UPLOAD_BYTES`, `MAX_PASTE_BYTES`, `MAX_EVENTS_PER_DATASET` | Upload/ingestion limits |
| `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX` | API rate limiting |
| `INTERNAL_CIDR_RANGES` | Comma-separated CIDR list overriding the default RFC1918/loopback/link-local ranges the CIDR evaluator treats as "internal" |
| `DETECTION_DB_PATH` | Path to the SQLite file backing the detection lifecycle (default `backend/data/detections.sqlite`; tests always use `:memory:`) |
| `ELASTICSEARCH_URL`, `ELASTICSEARCH_USERNAME`, `ELASTICSEARCH_PASSWORD`, `ELASTICSEARCH_API_KEY`, `ELASTICSEARCH_INDEX`, `ELASTICSEARCH_TIMEOUT_MS` (default `15000`) | Optional direct Elasticsearch fetch (Settings tab shows connection status); the timeout prevents a hung/unreachable cluster from hanging the server |
| `AI_PROVIDER` (`anthropic`\|`groq`\|`openai`\|`custom`), plus per-provider `ANTHROPIC_API_KEY`/`ANTHROPIC_MODEL`, `GROQ_API_KEY`/`GROQ_MODEL`, `OPENAI_API_KEY`/`OPENAI_MODEL`, or `AI_API_KEY`+`AI_BASE_URL`+`AI_MODEL` for a custom OpenAI-compatible endpoint | Optional AI-assist narrative text. Instead of env vars, a key can also be pasted into the **Settings** tab at runtime — that takes priority for the life of the running process and is never written to disk (see [Environment variables](#environment-variables) note below) |
| `AI_REQUEST_TIMEOUT_MS` (default `20000`), `AI_MAX_RETRIES` (default `2`) | How long to wait for an AI provider response, and how many times to retry a transient failure with backoff before falling back to the deterministic narrative |

## API

The frontend talks to a REST API under `/api` — see `backend/src/routes/api.js` for the full list. Key endpoints:

| Method & Path | Purpose |
|---|---|
| `GET /api/auth/status`, `POST /api/auth/login` (`{password}`), `POST /api/auth/logout` | Always reachable regardless of auth state - everything else under `/api` requires a valid session once `APP_PASSWORD` is set |
| `POST /api/sessions` | Ingest a file upload (`file` field) or pasted text (`{text, filename}`) |
| `POST /api/samples/:name/load` | Load a bundled sample dataset |
| `GET /api/sessions/:id/fields` | Field discovery results |
| `PUT /api/sessions/:id/mappings` | Set analyst-approved ECS mappings |
| `POST /api/sessions/:id/normalize` | Build normalized ECS events |
| `POST /api/sessions/:id/detect` | Run detection engineering analysis |
| `POST /api/sessions/:id/rules` | Generate a rule (`{detectionId, ruleType, indexPattern, severityOverride}`) |
| `POST /api/sessions/:id/rules/:ruleId/test` | Test a rule against the loaded dataset |
| `POST /api/sessions/:id/rules/:ruleId/testsuite` | Run/extend a labeled positive/negative/edge-case suite (`{testCases?, includeGenerated?}`) → PASS/FAIL/ERROR/SKIPPED per case + confusion matrix + precision/recall/F1/detection-rate/FP-rate |
| `GET /api/sessions/:id/rules/:ruleId/tune` | Get a tuning recommendation |
| `GET /api/sessions/:id/rules/:ruleId/report?format=json\|markdown\|csv` | Export the Detection Engineering Report |
| `GET /api/sessions/:id/dashboard` | Dashboard metrics |
| `GET /api/sessions/:id/detections/:detectionId/record` | Canonical Detection record for one detection (session-derived status unless persisted) |
| `POST /api/sessions/:id/detections/:detectionId/persist` | Start/refresh the durable lifecycle record for a detection (keyed by evaluator id, not the session) |
| `GET /api/detections`, `GET /api/detections/:evaluatorId`, `GET /api/detections/:evaluatorId/history` | List/inspect persisted detections and their lifecycle audit trail |
| `POST /api/detections/:evaluatorId/transition` | Move a persisted detection to a new lifecycle status (`{status, author, note}`) - rejected with 409 if the transition isn't valid (e.g. approving something never tested) |
| `GET/POST /api/elasticsearch/*` | Optional direct Elasticsearch integration |

## Security

- Upload validation: extension allowlist (`.json .jsonl .ndjson .txt .log .csv`), size limits, MIME sanity check. Nothing uploaded is ever executed.
- All JSON parsing is size- and depth-bounded before `JSON.parse` — never `eval`.
- Regexes are hand-reviewed for catastrophic-backtracking safety.
- Generated queries are built from an escaped, structured condition list and syntax-validated — never executed against a live system by this tool.
- Helmet security headers, per-IP rate limiting, generic (non-leaking) error responses.
- Elasticsearch credentials come only from environment variables, never hardcoded, never logged. AI provider keys come from environment variables or the Settings tab (session memory only, never written to disk) - never hardcoded, never logged, always masked when displayed back.
- **Prototype-pollution hardening (CWE-1321)**: analyst-editable ECS field mappings (`PUT /sessions/:id/mappings`) are rejected outright if they contain a `__proto__`/`constructor`/`prototype` path segment, with the same guard defensively applied everywhere a dotted field path is written (`utils/safePath.js`) - not just at the API boundary.
- **SSRF hardening**: a custom AI provider's base URL is rejected if it resolves to a cloud instance-metadata address (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`) - loopback and private-network addresses stay allowed, since pointing at a self-hosted local LLM is an intended use of the custom provider.
- Every outbound network call this app makes (AI provider, Elasticsearch) has a request timeout - none can hang the server indefinitely on an unreachable host. AI calls additionally retry transient failures (network error, 429, 5xx) with backoff; auth errors are never retried.
- No `child_process`/shell execution anywhere in the codebase - there is no command-injection surface to defend.
- **Observability**: every request gets a structured JSON log line (`request_id`, `method`, `route`, `status`, `duration_ms`, and - on an error response - the exact same sanitized message the client received) via `observability/requestLogger.js`. It logs metadata only, never a request body, so there is no code path by which a submitted password or API key reaches a log line.
- **Authentication**: opt-in via `APP_PASSWORD` (a single shared password, not multi-user accounts - deliberately, since this is a single-analyst workspace, not a SaaS product). A signed, `HttpOnly`/`SameSite=Strict` session cookie is issued on login; the password comparison uses `crypto.timingSafeEqual`, never a plain `===`, and is never echoed back in any response. Unset means no login at all, logged as a startup warning - see [Known limitations](#known-limitations-stated-honestly-not-hidden).

## Known limitations (stated honestly, not hidden)

- **CIDR-based internal/external traffic** is now a real, tested evaluator (`detection-engine/evaluators/cidrEvaluator.js`, IPv4 + IPv6, configurable range list) with a genuine `cidr` condition rendered into all 5 query languages — this one is no longer a gap.
- **DNS-tunneling** (length/entropy/character-distribution/subdomain-depth, `detection-engine/evaluators/dnsTunnelingEvaluator.js`) and **C2 beaconing timing regularity** (`detection-engine/evaluators/c2BeaconingEvaluator.js`) are now real, tested, deterministic evaluators with structured evidence — but their *generated query* still can only check that the relevant field exists, because entropy/character-distribution and multi-event timing regularity genuinely cannot be expressed as a static filter in KQL/EQL/ES|QL/Lucene/Sigma (that needs a scripted field or an aggregation pipeline, not a `WHERE` clause). This is a real limitation of static query languages, not an unfinished implementation — see the inline comments in `detection-engine/behaviors/networkBehaviors.js`.
- PDF report export is intentionally not implemented (JSON/Markdown/CSV are); a correct PDF renderer is a substantial dependency on its own.
- Log source identification and ECS mapping are confidence-scored heuristics, not guaranteed-correct — the UI always shows confidence and reasoning, and never presents an uncertain mapping or MITRE technique as definitive.
- **Detection lifecycle persistence is real but narrow, not general persistence.** A detection's approval/production status and version history now survive a restart via SQLite (`persistence/`) - but everything else (parsed events, mappings, normalized events, in-session detections/rules/test results) is still in-memory only, and on Render's free tier the SQLite file itself doesn't survive a deploy/spin-down unless it's on a mounted persistent disk.
- **The positive/negative/edge test-case framework validates a rule's own logic in isolation, not real-world coverage.** Auto-generated cases prove the rule matches what it says it matches and doesn't match an obviously different value - they cannot tell you whether the rule covers every real attacker variation, only whether its stated conditions behave as claimed.
- **Frontend test coverage is real but not exhaustive.** 38 unit tests (`frontend/tests/`, Node's built-in test runner + jsdom, no bundler) cover the pure/testable layer - `escapeHtml`/badge helpers, `resolveStage`'s pipeline-stage ladder, `api.js`'s error-taxonomy contract, and the pipeline-bar's done/current classification. On top of that, `e2e/` (Playwright + a real Chromium browser) drives the actual served UI against a real running backend: one test walks the entire pipeline from loading a sample dataset through generating, testing, and exporting a rule report; another exercises the opt-in-auth login/logout flow; a third checks a couple of frontend error paths. That's real coverage of the golden path and the auth flow, but not of every tab's every interaction/edge case - there's no attempt at exhaustive UI coverage.
- **Authentication is real but intentionally minimal**: one shared password (`APP_PASSWORD`), not per-analyst accounts - there's no username, no audit trail of *who* approved a detection beyond the free-text `author` field callers can set on their own, and no way to revoke a single session early (no server-side session table to delete from) short of changing `SESSION_SECRET`, which invalidates every session at once including your own, or waiting out the 12-hour TTL. This is a deliberate scope boundary for a single-analyst tool, not an oversight - see [ARCHITECTURE_AUDIT.md](ARCHITECTURE_AUDIT.md) for the full maturity assessment and roadmap.

---

<div align="center">

Built as a real detection engineering workflow, not a chatbot wrapper.

</div>
