# Architecture

SOC Detection Copilot is a Node.js/Express backend plus a static (vanilla JS,
no build step) dark-themed frontend. There is no framework, ORM, or database:
each analyst session lives in an in-memory store keyed by a session ID, since
this is a single-analyst workspace tool, not a multi-tenant SaaS product.

```
Elastic export / upload / paste / sample dataset
        |
        v
  ingestion/            LogSource abstraction (FileUpload, Paste,
                         SampleDataset, Elasticsearch) + multer upload
                         validation (extension, size, MIME)
        |
        v
  parsing/               format detection (json / ndjson / csv / plain),
                         safe bounded JSON parsing, event extraction
        |
        v
  field-discovery/        flattens nested events to dotted paths, infers
                         value types (ip/date/port/email/...), computes
                         frequency/null%, calls into ecs-mapping for a
                         candidate ECS field per raw field
        |
        v
  ecs-mapping/            deterministic alias-dictionary + value-type
                         validation -> {ecsField, confidence, reason,
                         status: confident|uncertain|unmapped}
        |
        v
  log-source-id/          scores raw events against declarative source
                         signatures (Linux SSH, Windows Security, Sysmon,
                         Apache/Nginx/IIS, firewalls, DNS, cloud, ...)
        |
        v
  normalization/           applies analyst-approved mappings to build the
                         nested ECS event (renaming + light type coercion)
        |
        v
  detection-engine/       behaviors/{auth,linux,windows,network,web,
                         firewall}.js each scan normalized events for one
                         family of suspicious activity and emit Detection
                         Candidates (severity, confidence, evidence,
                         recommendedThreshold, and the exact ruleConditions
                         that reproduce the match)
        |
        v
  mitre/                  static, reviewable hint -> {tactic, technique}
                         lookup table; low-confidence mappings are always
                         marked uncertain, never presented as definitive
        |
        v
  rule-generation/         renders a detection's ruleConditions into KQL /
                         ES|QL / EQL / Lucene / Sigma, with proper OR-list
                         and "field exists" support, plus the full rule
                         structure (risk score, index, schedule, threshold,
                         investigation steps, FP guidance, references)
        |
        v
  rule-validation/         non-executing syntax validation (balanced
                         delimiters, no destructive/template-injection
                         constructs, per-language structural checks)
        |
        v
  testing/                executes a rule's structured conditions (not its
                         query text - no query-language interpreter, no
                         eval) against the normalized events, with count or
                         distinct-count threshold/grouping support
        |
        v
  false-positive/          cross-checks rule matches against the
                         originating detection's own evidence to flag
                         "potential false positives requiring review",
                         plus static per-detection-type FP guidance
        |
        v
  tuning/                  proportional threshold-increase recommendation
                         when the measured FP rate exceeds 10%, validated
                         by re-running the rule at the new threshold
        |
        v
  investigation/           static per-category investigation checklists
        |
        v
  reporting/               assembles the final Detection Engineering
                         Report and renders JSON / Markdown / CSV; also
                         aggregates the dashboard metrics
```

## Why deterministic-first

Per the project's design goal, every calculation that *can* be done
deterministically *is*: JSON/NDJSON/CSV parsing, IP/timestamp/port
validation, ECS mapping confidence, MITRE mapping, statistics (match rate,
false-positive rate), and rule syntax validation are all plain code with
unit tests - none of it calls an LLM. `src/ai/aiAssist.js` is the only place
that talks to a model, and only for optional narrative text (a short
analyst-facing explanation of a detection, or a note on an uncertain ECS
mapping); every one of its functions has a deterministic fallback and the
app works identically with `ANTHROPIC_API_KEY` unset.

This is an architectural guarantee, not just a convention: AI output is
narrative-only and flows in one direction. Every AI/provider call site
(`ai/aiAssist.js`'s three explain functions, plus the `/ai/test` connection
check) terminates in a plain `res.json(...)` response - none of them ever
assign their result onto `session.detections[...]`, `session.mappings[...]`,
a rule's `query`/`conditions`/`queryValid`, or into
`persistence/detectionStore.js`'s `upsertFromDetectionRecord`/`transition`
(those two are only ever called with values built from deterministic session
state or from an explicit analyst request body - never from an AI response).
A detection's severity, confidence, MITRE mapping, ECS mapping, generated
query, test results, and persisted lifecycle status are therefore
structurally impossible for an AI response to alter.

The provider layer (`ai/providers.js`, `ai/aiErrors.js`) is hardened
independently of that guarantee: every call has a request timeout
(`AI_REQUEST_TIMEOUT_MS`) and a bounded retry policy with backoff
(`AI_MAX_RETRIES`) for transient failures (network error, timeout, 429,
5xx), honoring a provider's `Retry-After` header when present. Auth errors
(401/403) and other 4xx errors are never retried. Every failure is a typed
error (`AiTimeoutError`/`AiNetworkError`/`AiRateLimitError`/`AiAuthError`/
`AiServerError`) with a stable `.code` and `.retryable` flag, so a caller
(or the Settings UI) can distinguish "try again" from "fix your key"
without parsing a message string.

## The `ruleConditions` design (why rules actually test correctly)

Early in development, rule generation used a single hint -> generic
condition dictionary (`rule-generation/queryConditions.js`). That produced
syntactically valid rules that did not reproduce what the detection engine
actually matched on - e.g. a "Reverse Shell Indicator" detection (matched by
scanning `message` for `/dev/tcp/`) generated a rule filtered on
`event.category: "process"`, which nothing in the sample data had, so
"test against sample logs" always reported zero matches for that rule.

Every behavior in `detection-engine/behaviors/*.js` now attaches its own
`ruleConditions` to each Detection Candidate - the *same* field(s) and
value(s) (or OR-list of values, or a plain "field exists" check for
cardinality-only signals like port scanning) it used to identify the
behavior. `rule-generation/ruleBuilder.js` uses `detection.ruleConditions`
when present, falling back to the generic dictionary only for detections
that don't set one. This is why the rule testing/false-positive/tuning
numbers you see in the UI are meaningful rather than cosmetic. A few
detections (internal-to-external CIDR comparison, DNS-tunneling
entropy/length, C2 beaconing timing regularity) genuinely cannot be
expressed by simple field/value/exists conditions - those are documented
inline in the relevant behavior file and the generated query is a
best-effort starting point the analyst is expected to refine, not a
finished production rule.

## Session model

`pipeline/sessionStore.js` holds an in-memory `Map<sessionId, session>`
where a session accumulates state as the analyst moves through the pipeline
(parsed events -> field discovery -> approved mappings -> normalized events
-> detections -> generated rules -> test results -> tuning). Sessions
expire after 2 hours of inactivity and none of this survives a restart -
appropriate for a single-analyst workspace, not concurrent multi-user
production use.

The one thing that *is* durable is the detection lifecycle
(`detections/detectionLifecycle.js` + `persistence/detectionStore.js`, a
small SQLite database). A detection's identity for lifecycle purposes is
its `evaluator.id` (`${category}.${mitreHint}` - the detection *type*, not
one session's specific instance of it), so approving "SSH Brute Force"
once means every future session that flags it again sees the same
persisted status, version, and audit history, independent of the
inherently-ephemeral session data around it. See
`persistence/db.js`'s module comment for why this is deliberately scoped
to lifecycle state only, not general app persistence.

## Frontend

Plain ES modules, no build step, no framework - `frontend/js/app.js` wires
up 13 tab modules (`frontend/js/tabs/*.js`) against a small `state.js`
store and an `api.js` fetch wrapper. Every place that inserts
externally-derived text (log fields, messages) into the DOM goes through
`escapeHtml()` in `utils.js` first.

## Security posture

- File uploads are extension-allowlisted and size-limited (multer, in
  `ingestion/upload.js`); nothing uploaded is ever executed.
- All JSON parsing goes through `parsing/safeJson.js`, which bounds input
  size and nesting depth before calling `JSON.parse` - never `eval`.
- Regexes used for log-source/behavior detection are hand-reviewed to avoid
  catastrophic backtracking (bounded quantifiers, no nested `.*.*`).
- Generated queries are built from an escaped, structured condition list -
  never string-concatenated from raw analyst/log input - and are validated
  (not executed) before display.
- Helmet security headers, per-IP rate limiting, and a generic error
  handler that never reflects internal error details back to the client.
- Elasticsearch/AI credentials are read only from environment variables and
  are never logged, echoed, or hardcoded.
