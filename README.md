<div align="center">

# 🛡️ SOC Detection Copilot

**A practical SOC Analyst / Detection Engineer workspace.**
Take raw logs exported from Elastic — or uploaded/pasted from anywhere — and run them through a real, end-to-end detection engineering workflow: field discovery, ECS mapping, behavioral detection, MITRE ATT&CK mapping, rule generation, testing, false-positive analysis, and tuning.

![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![Tests](https://img.shields.io/badge/tests-149%20passing-brightgreen)
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
| **Rule Validation** | Syntax-checked — never executed against a live system by this tool |
| **Rule Testing** | Run against your own loaded logs for real match counts |
| **False Positive Analysis** | Potential FPs cross-checked against the detection's own evidence |
| **Tuning** | Threshold recommendation with a real before/after re-test |
| **Report** | Exportable JSON / Markdown / CSV Detection Engineering Report |

## Features

- 🗂️ **Multi-source ingestion** — file upload, paste, 8 bundled sample datasets, or a direct Elasticsearch fetch (all optional, all env-configured)
- 🔍 **Log source identification** — Linux SSH, Windows Security, Sysmon, Apache/Nginx/IIS, firewalls (Fortinet/Palo Alto/Cisco/generic), DNS, DHCP, VPN, proxy, EDR, cloud (CloudTrail/Azure/M365), database, and custom application logs
- 🧭 **Analyst-in-the-loop ECS mapping** — every suggestion shows its confidence and reasoning, and can be overridden before normalization
- 🕵️ **6 behavior families, 25+ individual detections** — brute force, password spraying, privileged auth, reverse shells, suspicious sudo, encoded/suspicious PowerShell, LOLBins, credential dumping, persistence (services/scheduled tasks/registry run keys/cron), port scanning, DNS tunneling, C2 beaconing, SQLi/XSS/path traversal/web shells, and firewall anomalies
- 🎯 **MITRE ATT&CK mapping** that never overstates confidence
- 📝 **5 query languages** generated per detection: KQL, ES\|QL, EQL, Lucene, Sigma
- ✅ **Real rule testing** — each detection carries the exact structured conditions that reproduced its own match, so "test against sample logs" reflects reality instead of a generic placeholder
- 📊 **SOC-style dashboard** — logs processed, mapping coverage, detections, rules validated, MITRE technique count, high-risk findings
- 🌓 **Dark SOC/SIEM-themed UI** — 13 tabs, no build step, no framework
- ✨ **Multi-provider AI assist** — Claude, Groq, OpenAI, or any other OpenAI-compatible API; configure via environment variables or paste a key straight into the **Settings** tab (session-memory only, never written to disk, always masked when shown back). Powers optional "Explain with AI" buttons on detections and false-positive analysis — every one of them has a deterministic fallback when no key is set
- 🔒 **Security-first**: upload allowlisting/size limits, bounded JSON parsing, catastrophic-backtracking-safe regexes, escaped/validated (never executed) query generation, rate limiting, and env-var-only secrets

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

The whole app is a single stateless-ish Node/Express process (in-memory sessions, 2-hour TTL, no database), so it deploys to any host that can run `node backend/src/server.js` and keep it alive. [Render](https://render.com) is the easiest free option:

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/hamzakhan947075/soc-detection-copilot)

1. Click the button above (or **New +** → **Blueprint** on Render and point it at this repo) — it reads [`render.yaml`](render.yaml), which builds/starts from `backend/`.
2. Wait for the first deploy to finish, then open the `.onrender.com` URL Render gives you.
3. Nothing else is required — every environment variable is optional. If you want AI-assist or a live Elasticsearch connection in the deployed app, either add them as environment variables in the Render dashboard (see the table below), or just open the deployed app's **Settings** tab and paste an API key in directly (session-memory only, never written to disk).

Free-tier note: Render's free web services spin down after 15 minutes of inactivity and cold-start on the next request (session data does not survive a spin-down/restart, same as restarting it locally).

Any other Node host works the same way (Railway, Fly.io, a plain VPS with `pm2`/`systemd`, etc.) — just set the working directory to `backend/`, run `npm install && npm start`, and make sure the platform's assigned `PORT` reaches the process (the app already reads `process.env.PORT`).

## Running tests

```bash
cd backend
npm test              # 149 tests across parsing, field discovery, ECS
                       # mapping, detection engine, MITRE mapping, rule
                       # generation/validation, rule testing, false-positive
                       # analysis, tuning, AI provider config, and API/upload security
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
    detection-engine/  behaviors/{auth,linux,windows,network,web,firewall}.js
    detections/        canonical Detection record (additive) + evaluator result contract
    mitre/             static hint -> {tactic, technique} lookup
    rule-generation/   KQL/ES|QL/EQL/Lucene/Sigma builders + rule assembly
    rule-validation/   non-executing syntax validation
    testing/           executes a rule's structured conditions against events
    false-positive/    dynamic FP analysis + static FP guidance
    tuning/             threshold tuning recommendation
    investigation/     per-category investigation checklists
    reporting/          Detection Engineering Report + dashboard aggregation
    ai/                 multi-provider (Claude/Groq/OpenAI/custom) narrative assist
    security/          helmet, rate limiting, safe error handler
    pipeline/          session store + orchestration + pipeline stage metadata
    routes/            Express API
  sample-data/         8 bundled sample datasets
  tests/               149 tests (see above)
frontend/
  js/
    api.js, state.js, controller.js, pipelineBar.js, utils.js
    tabs/              13 tab modules: Overview, Log Ingestion, Field
                       Discovery, ECS Mapping, Detection Engineering, MITRE
                       ATT&CK, Rule Builder, Rule Testing, False Positive
                       Analysis, Detection Tuning, Investigation, Reports,
                       Settings
  index.html, styles.css   dark SOC/SIEM-styled UI, no build step
ARCHITECTURE.md         data flow, design rationale, security posture
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full data-flow diagram and design rationale (in particular, why rule generation is keyed off a per-detection `ruleConditions` field rather than a generic lookup table).

## Environment variables

All optional — copy `backend/.env.example` to `backend/.env`. Nothing here is required to run the full pipeline against uploaded/pasted/sample data.

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port (default `4000`) |
| `MAX_UPLOAD_BYTES`, `MAX_PASTE_BYTES`, `MAX_EVENTS_PER_DATASET` | Upload/ingestion limits |
| `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX` | API rate limiting |
| `ELASTICSEARCH_URL`, `ELASTICSEARCH_USERNAME`, `ELASTICSEARCH_PASSWORD`, `ELASTICSEARCH_API_KEY`, `ELASTICSEARCH_INDEX` | Optional direct Elasticsearch fetch (Settings tab shows connection status) |
| `AI_PROVIDER` (`anthropic`\|`groq`\|`openai`\|`custom`), plus per-provider `ANTHROPIC_API_KEY`/`ANTHROPIC_MODEL`, `GROQ_API_KEY`/`GROQ_MODEL`, `OPENAI_API_KEY`/`OPENAI_MODEL`, or `AI_API_KEY`+`AI_BASE_URL`+`AI_MODEL` for a custom OpenAI-compatible endpoint | Optional AI-assist narrative text. Instead of env vars, a key can also be pasted into the **Settings** tab at runtime — that takes priority for the life of the running process and is never written to disk (see [Environment variables](#environment-variables) note below) |

## API

The frontend talks to a REST API under `/api` — see `backend/src/routes/api.js` for the full list. Key endpoints:

| Method & Path | Purpose |
|---|---|
| `POST /api/sessions` | Ingest a file upload (`file` field) or pasted text (`{text, filename}`) |
| `POST /api/samples/:name/load` | Load a bundled sample dataset |
| `GET /api/sessions/:id/fields` | Field discovery results |
| `PUT /api/sessions/:id/mappings` | Set analyst-approved ECS mappings |
| `POST /api/sessions/:id/normalize` | Build normalized ECS events |
| `POST /api/sessions/:id/detect` | Run detection engineering analysis |
| `POST /api/sessions/:id/rules` | Generate a rule (`{detectionId, ruleType, indexPattern, severityOverride}`) |
| `POST /api/sessions/:id/rules/:ruleId/test` | Test a rule against the loaded dataset |
| `GET /api/sessions/:id/rules/:ruleId/tune` | Get a tuning recommendation |
| `GET /api/sessions/:id/rules/:ruleId/report?format=json\|markdown\|csv` | Export the Detection Engineering Report |
| `GET /api/sessions/:id/dashboard` | Dashboard metrics |
| `GET/POST /api/elasticsearch/*` | Optional direct Elasticsearch integration |

## Security

- Upload validation: extension allowlist (`.json .jsonl .ndjson .txt .log .csv`), size limits, MIME sanity check. Nothing uploaded is ever executed.
- All JSON parsing is size- and depth-bounded before `JSON.parse` — never `eval`.
- Regexes are hand-reviewed for catastrophic-backtracking safety.
- Generated queries are built from an escaped, structured condition list and syntax-validated — never executed against a live system by this tool.
- Helmet security headers, per-IP rate limiting, generic (non-leaking) error responses.
- Elasticsearch credentials come only from environment variables, never hardcoded, never logged. AI provider keys come from environment variables or the Settings tab (session memory only, never written to disk) - never hardcoded, never logged, always masked when displayed back.

## Known limitations (stated honestly, not hidden)

- A handful of detections (CIDR-based internal/external traffic, DNS-tunneling entropy/length, C2 beaconing timing regularity) can't be fully expressed by the simplified `{field, value}` rule-condition model; their generated queries are a documented starting point, not a finished production rule — see the inline comments in `detection-engine/behaviors/`.
- PDF report export is intentionally not implemented (JSON/Markdown/CSV are); a correct PDF renderer is a substantial dependency on its own.
- Log source identification and ECS mapping are confidence-scored heuristics, not guaranteed-correct — the UI always shows confidence and reasoning, and never presents an uncertain mapping or MITRE technique as definitive.

---

<div align="center">

Built as a real detection engineering workflow, not a chatbot wrapper.

</div>
