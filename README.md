# SOC Detection Copilot

A practical **SOC Analyst / Detection Engineer workspace**: take raw logs
exported from Elastic (or uploaded/pasted from anywhere), and run them
through a real end-to-end detection engineering workflow -

```
Raw Logs
  -> Parsing (format detection, safe JSON/NDJSON/CSV parsing)
  -> Field Discovery (types, frequency, null %, security relevance)
  -> ECS Mapping (deterministic confidence-scored suggestions, analyst-editable)
  -> Normalization (raw event -> normalized ECS event, side-by-side diff)
  -> Detection Engineering (auth / linux / windows / network / web / firewall behaviors)
  -> MITRE ATT&CK Mapping (static, explainable, uncertainty always flagged)
  -> Rule Generation (KQL / ES|QL / EQL / Lucene / Sigma)
  -> Rule Validation (syntax-checked, never executed against a live system)
  -> Rule Testing (against your own loaded logs - real match counts)
  -> False Positive Analysis (potential FPs cross-checked against evidence)
  -> Tuning (threshold recommendation with before/after re-test)
  -> Production-Ready Detection (exportable JSON/Markdown/CSV report)
```

This is not a generic "paste logs, get an AI answer" tool. Every calculation
that can be deterministic *is* deterministic (parsing, ECS confidence,
detection thresholds, MITRE mapping, rule syntax validation, statistics);
an LLM is only ever used, optionally, for supplementary narrative text.

## Quick start

```bash
cd backend
npm install
cp .env.example .env      # optional - the app works with no configuration
npm start                 # -> http://localhost:4000
```

Open `http://localhost:4000`, go to **Log Ingestion**, and click one of the
**sample dataset** chips (SSH, Windows Security, Sysmon, Apache, Nginx,
Firewall, DNS, generic Authentication) to run the full pipeline without
needing an Elastic cluster.

To use your own data: upload a `.json` / `.jsonl` / `.ndjson` / `.txt` /
`.log` / `.csv` file, or paste raw events directly. The app does **not**
assume your logs are already ECS-compliant, and understands common Elastic
export shapes (`message`, `event.original`, `log.original`).

## Running tests

```bash
cd backend
npm test              # 86 tests across parsing, field discovery, ECS
                       # mapping, detection engine, MITRE mapping, rule
                       # generation/validation, rule testing, false-positive
                       # analysis, tuning, and API/upload security
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
    mitre/             static hint -> {tactic, technique} lookup
    rule-generation/   KQL/ES|QL/EQL/Lucene/Sigma builders + rule assembly
    rule-validation/   non-executing syntax validation
    testing/           executes a rule's structured conditions against events
    false-positive/    dynamic FP analysis + static FP guidance
    tuning/             threshold tuning recommendation
    investigation/     per-category investigation checklists
    reporting/          Detection Engineering Report + dashboard aggregation
    ai/                 optional Anthropic-backed narrative assist
    security/          helmet, rate limiting, safe error handler
    pipeline/          session store + orchestration + pipeline stage metadata
    routes/            Express API
  sample-data/         8 bundled sample datasets
  tests/               86 tests (see above)
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

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full data-flow diagram and
design rationale (in particular, why rule generation is keyed off a
per-detection `ruleConditions` field rather than a generic lookup table).

## Environment variables

All optional - copy `backend/.env.example` to `backend/.env`. Nothing here
is required to run the full pipeline against uploaded/pasted/sample data.

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port (default `4000`) |
| `MAX_UPLOAD_BYTES`, `MAX_PASTE_BYTES`, `MAX_EVENTS_PER_DATASET` | Upload/ingestion limits |
| `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX` | API rate limiting |
| `ELASTICSEARCH_URL`, `ELASTICSEARCH_USERNAME`, `ELASTICSEARCH_PASSWORD`, `ELASTICSEARCH_API_KEY`, `ELASTICSEARCH_INDEX` | Optional direct Elasticsearch fetch (Settings tab shows connection status) |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` | Optional AI-assist narrative text |

## API

The frontend talks to a REST API under `/api` - see `backend/src/routes/api.js`
for the full list. Key endpoints:

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
- All JSON parsing is size- and depth-bounded before `JSON.parse` - never `eval`.
- Regexes are hand-reviewed for catastrophic-backtracking safety.
- Generated queries are built from an escaped, structured condition list and syntax-validated - never executed against a live system by this tool.
- Helmet security headers, per-IP rate limiting, generic (non-leaking) error responses.
- Elasticsearch/AI credentials come only from environment variables, never hardcoded, never logged.

## Known limitations (stated honestly, not hidden)

- A handful of detections (CIDR-based internal/external traffic, DNS-tunneling entropy/length, C2 beaconing timing regularity) can't be fully expressed by the simplified `{field, value}` rule-condition model; their generated queries are a documented starting point, not a finished production rule - see the inline comments in `detection-engine/behaviors/`.
- PDF report export is intentionally not implemented (JSON/Markdown/CSV are); a correct PDF renderer is a substantial dependency on its own.
- Log source identification and ECS mapping are confidence-scored heuristics, not guaranteed-correct - the UI always shows confidence and reasoning, and never presents an uncertain mapping or MITRE technique as definitive.
