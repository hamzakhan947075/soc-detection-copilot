# Architecture Audit — SOC Detection Copilot

**Date:** 2026-08-19
**Baseline:** `main` @ `9055a35`, 125 backend tests passing (9 suites), 0 frontend tests.
**Scope:** Full backend + frontend inspection, read-only. No code was changed while producing this document.

This audit exists to guide real engineering decisions on maturing the project. It is deliberately honest about what's thin, duplicated, or fragile — the goal is a credible workbench, not a flattering document.

---

## 1. Current architecture

Single Node/Express process, no framework, no database. A request comes in, moves through a linear pipeline of plain-function modules, and results are held in an in-memory session `Map`. The frontend is 13 vanilla ES-module tabs polling a REST API under `/api`, with no client-side framework or build step.

```
Elastic export / upload / paste / sample / ES fetch
        │
        ▼
  ingestion/          LogSource abstraction (upload/paste/sample unified;
                      Elasticsearch fetch bypasses it, see §4)
        │
        ▼
  parsing/            format detection → bounded JSON parse → event array
        │
        ▼
  field-discovery/    flatten → infer types → per-field stats → ECS candidate
        │
        ▼
  ecs-mapping/        alias dictionary + confidence scoring
        │
        ▼
  log-source-id/      weighted signature scoring → source + evidence
        │
        ▼
  normalization/      approved mappings → nested ECS event (+ light coercion)
        │
        ▼
  detection-engine/   6 behavior families → Detection Candidates (+ ruleConditions)
        │
        ▼
  mitre/              static hint → {tactic, technique, confidence} lookup
        │
        ▼
  rule-generation/    ruleConditions → KQL/ES|QL/EQL/Lucene/Sigma
        │
        ▼
  rule-validation/    non-executing syntax checks
        │
        ▼
  testing/            executes structured conditions against normalized events
        │
        ▼
  false-positive/     matched-but-not-in-evidence set difference + static guidance
        │
        ▼
  tuning/             proportional threshold suggestion + real re-test
        │
        ▼
  reporting/          per-rule report (JSON/Markdown/CSV) + dashboard aggregation
```

Everything left of `rule-generation` is genuinely deterministic and unit-tested. AI (`ai/`) sits outside this spine entirely — it's called from `routes/api.js` on demand for narrative text only, never from inside the pipeline.

## 2. Module responsibilities (as-built, not aspirational)

| Module | Owns | Does not own |
|---|---|---|
| `ingestion/` | Upload validation, source normalization (3 of 4 paths), sample dataset lookup | Elasticsearch fetch shaping (lives in `elasticsearchClient.js` + inline in `routes/api.js`) |
| `parsing/` | Format detection, bounded JSON parsing, NDJSON/CSV/plain extraction | Field-level interpretation |
| `field-discovery/` | Flattening, type inference, per-field stats, ECS candidate lookup | The ECS schema itself (delegates to `ecs-mapping/`) |
| `ecs-mapping/` | Schema dictionary (~150 fields), alias dictionary, confidence scoring, metadata/`.text` handling | Applying mappings to events (that's `normalization/`) |
| `log-source-id/` | Weighted signature scoring against 20 declarative source definitions | Field discovery itself |
| `normalization/` | Mapping application, light type coercion | Validating that coerced values are actually well-formed (see §6) |
| `detection-engine/` | 29 detections across 6 behavior files, each producing a Detection Candidate with its own `ruleConditions` | A canonical Detection *record* — see §5, this is the single biggest structural gap |
| `mitre/` | Static hint→technique lookup, confidence flag | Sub-technique as a distinct field (folded into the ID string) |
| `rule-generation/` | Per-language query rendering from `ruleConditions` | A shared query AST — each language re-implements clause-building independently |
| `rule-validation/` | Syntax/delimiter/dangerous-pattern checks | Semantic checks (unknown fields, contradictory conditions, broad-query warnings) |
| `testing/` | Structured-condition matching against events | Positive/negative/edge-case test *case* management — today's "testing" only means "run this rule against whatever's loaded" |
| `false-positive/` | Aggregate FP rate + static per-detection-type guidance | Any dynamic breakdown by field/user/host/process/destination |
| `tuning/` | Proportional threshold suggestion, real re-test of the new threshold's match count | Re-verifying the new threshold's FP rate (only match count is re-tested, not FP rate) |
| `reporting/` | Single-rule/detection report; dashboard aggregate metrics | Session-wide "generated rules" rollup, executive summary, limitations section |
| `ai/` | Multi-provider adapter, session-memory key store, narrative-only assist functions | Nothing in the deterministic pipeline — confirmed clean separation |
| `pipeline/` | `sessionStore` (Map+TTL), `pipelineOrchestrator` (storage-agnostic ingest/mappings/normalize) | Route-level session mutation (lives directly in `routes/api.js`, see §4) |
| `security/` | Helmet, rate limiting, central error sanitizer | Not applied uniformly — several routes bypass it (see §7) |

## 3. Data flow & dependency flow

Data flow is a straight line (see §1 diagram) with one real branch: Elasticsearch-sourced events skip `logSource.js`'s abstraction and are serialized/re-ingested as a JSON blob directly in `routes/api.js`. Dependency flow is mostly one-directional and clean — `pipelineOrchestrator.js` imports only `parsing/`, `field-discovery/`, `log-source-id/`, `normalization/`, and `ecs-mapping/` (for the shared `ECS_FIELDS` type lookup), with zero import of `sessionStore` or Express. **This is the project's best architectural asset**: the orchestrator is a genuinely storage-agnostic seam. The actual coupling to the in-memory model lives entirely in `routes/api.js`, which does direct property writes on session objects (`session.mappings = ...`, `session.rules.set(...)`) and in `dashboard.js`, which assumes `session.rules` is literally a JS `Map`.

## 4. Major technical debt

1. **No canonical Detection record.** A Detection Candidate (`candidateFactory.js`) and a generated Rule (`ruleBuilder.js`) are separate, loosely-linked objects assembled ad hoc per request. There is no persisted, versioned "Detection" entity with lifecycle/status/history — every one of Phases 2–4's requirements (structured detection model, lifecycle, versioning) starts from zero here, not from a refactor.
2. **Elasticsearch ingestion bypasses the `LogSource` abstraction** (`routes/api.js` calls `esClient.fetchLogs()` then `JSON.stringify` → `ingest()` directly), so "3 of 4" ingestion paths share code and the 4th is a special case that will drift if `logSource.js` changes.
3. **The three explicitly-disclosed detection gaps are real and specific**: DNS tunneling, C2 beaconing, and CIDR internal/external comparison each compute a genuine signal in the detection engine (entropy, interval regularity, address family) but the *generated rule* silently degrades to a bare `exists` check — the computed signal never reaches the exported query. This is exactly Phase 3's target and is well-scoped to fix.
4. **Query-language rendering has no shared AST.** Five renderers (`buildKql/buildEsql/buildEql/buildLucene/buildSigma`) each re-implement the same `exists / values-OR / equality` branching independently, differing only in join tokens. A new condition shape (e.g. a range comparison for the CIDR evaluator) means five near-identical edits, not one.
5. **`ruleTester.js`'s condition matching is a case-insensitive substring match**, not the exact-equality its own rendered KQL/EQL text visually implies (`field:"value"` reads as exact-match, but testing accepts substrings). This is a correctness risk, not just a debt item — see §6.
6. **Coerced-but-invalid values are silently written into normalized events.** `normalizer.js` marks `coerced: false` when a value doesn't validate for its ECS type, but still writes the raw value into the ECS path unchanged — "not coerced" and "invalid" are conflated.
7. **Unmapped/dropped fields never reach the detection engine.** `runDetectionEngine` only sees `session.normalizedEvents`; a field that's genuinely relevant but unmapped (or dropped because `rawField` wasn't present under that exact key) is invisible to every behavior module, silently.
8. **FP analysis has no dimensional breakdown** — it's a single aggregate rate plus a raw matched-index list, not the field/user/host/process/destination breakdown Phase 12 asks for. `fpGuidance.js`'s static per-type guidance is entirely disconnected from the dynamic per-run numbers.
9. **Tuning's suggested threshold is a blind proportional-scaling formula**, not a search over the real threshold/FP curve, and the "after" re-test only re-checks match count — it never re-runs FP analysis at the new threshold to confirm the ≤10% target was actually hit.

## 5. Duplicated logic (concrete instances)

- `truncate(str, max)` copy-pasted verbatim in `linuxBehaviors.js`, `windowsBehaviors.js`, `webBehaviors.js` — not hoisted.
- Confidence-score formula (`min(cap, base + n·coef)`) reimplemented with different magic constants in at least 4 behavior files.
- C2/suspicious-port lists are duplicated **and inconsistent** between `networkBehaviors.js` (6 ports) and `firewallBehaviors.js` (4 ports, missing two) — they will silently drift further apart.
- `flattenEvent()` is recomputed redundantly at three separate pipeline stages (field discovery, once per event *per source-definition* inside log-source scoring, and again in normalization) with no caching.
- ECS coverage-percentage math duplicated verbatim in `pipelineOrchestrator.js` and `dashboard.js`.
- `round2()` reimplemented independently in `fieldDiscovery.js` and `sourceIdentifier.js`.
- Frontend: badge-class mapping (`low/medium/high/critical` → CSS class) is hand-rolled inline in `mitre.js`, `ruleBuilder.js`, `ruleTesting.js`, and `falsePositive.js`, each slightly differently, instead of using `utils.js`'s existing `statusBadge`/`severityBadge` helpers. "No data yet" empty-state markup and stat-card markup are each duplicated across 5–8 tab files with no shared helper.

## 6. Correctness risks

- **`ruleTester.js` substring-vs-equality mismatch** (§4.5): a condition `{field:'user.name', value:'root'}` will match `user.name:'rootkit'` during testing, inflating true-positive counts and understating false positives for any field where one value is a substring of another (usernames, hostnames, process names are all exposed to this).
- **Silent no-match on field-name drift**: every behavior hardcodes ECS dotted-path literals; if a field arrives under a valid-but-different alias, the behavior simply doesn't fire, with no warning surfaced anywhere.
- **IPv4-only privacy check** (`isPrivateIp`) — no IPv6 handling in network/firewall behaviors, meaning the CIDR evaluator work in Phase 3 needs to introduce IPv6 support net-new, not extend existing logic.
- **Elasticsearch route error leakage**: `elasticsearch/*` and `ai/test` routes catch their own errors and return `err.message` directly instead of routing through the sanitizing `errorHandler` — a hung/misconfigured ES host can leak internal DNS/TLS error strings to the client, contradicting the project's own stated security posture.
- **Parsing size-cap mismatch**: multer allows uploads up to 25MB but `safeJsonParse`'s bound (reused from the 10MB paste limit) rejects JSON/NDJSON parsing above 10MB — a 15MB well-formed NDJSON file passes upload, then silently degrades to being ingested as one giant plain-text event.
- **NDJSON doesn't trim a BOM** before the first line's `JSON.parse`, while the JSON-array path does — a well-formed BOM-prefixed NDJSON file's first record silently fails to parse.

## 7. Security risks

- Confirmed solid: upload allowlist + size limit + weak MIME denylist, bounded/depth-limited JSON parsing, sample-dataset path-traversal defense (tested), helmet + CSP, per-IP rate limiting, no hardcoded secrets, AI keys never logged/returned raw/persisted to disk.
- **Real gap**: the `elasticsearch/*` and `ai/test` routes bypass the central error sanitizer (§6) — the one concrete place internal error detail can reach a client today.
- **Real gap**: no bounds-checking on numeric env vars (`RATE_LIMIT_MAX`, `MAX_UPLOAD_BYTES`, etc.) — a misconfigured deployment could accept nonsensical values silently.
- No SSRF exposure found: the Elasticsearch target URL is env-only, never derived from request input.
- No ReDoS exposure found: value-type regexes are reviewed, anchored, length-gated, no nested quantifiers.
- No frontend double-submit protection: every primary action button (generate rule, run test, tune, approve mappings) can be triggered twice concurrently with no disabled-state guard.

## 8. Scalability / production-readiness limitations

- In-memory session `Map`, no persistence — a restart (or, on Render's free tier, an idle spin-down) loses every in-progress session. `pipelineOrchestrator.js` is already storage-agnostic; the coupling to fix is in `routes/api.js` and `dashboard.js`.
- No authentication of any kind — any request holding a valid session ID has full read/write access to that session's data. Fine for a single local analyst; not fine for a shared URL.
- No CI — tests are only ever run manually; nothing prevents a regression from reaching `main`.
- No structured logging/observability beyond `console.error` on unhandled errors; no request IDs, no per-stage timing.
- Frontend has zero automated test coverage of any kind.

## 9. Testing gaps

- **Detection engine**: 9 of 29 behaviors have direct engine-level test coverage. Zero coverage for Privileged Auth, New User Creation, Cron Persistence, Suspicious PowerShell, LOLBins, Service Creation, Scheduled Task, Registry Run-Key, XSS, Path Traversal, Web Shell, Suspicious Methods, Auth Abuse — and, notably, **all three explicitly-disclosed approximate detections** (DNS Tunneling, C2 Beaconing, Internal→External CIDR) have no test at all today.
- **Query generation**: `buildLucene` and `buildEql` (2 of 5 renderers) have zero test coverage anywhere.
- **MITRE**: no test asserts that every `mitreHint` string actually emitted by the 6 behavior files resolves in `MITRE_LOOKUP` — a typo in a new detection would silently fall through to "no mapping" with nothing catching it.
- **FP analysis**: only high-risk and zero-FP bands are tested; the medium-risk band (15–39%) is unasserted. `fpGuidance.js` has no dedicated tests.
- **Frontend**: zero automated tests of any kind — no startup smoke test, no upload-workflow test, no tab-rendering test.
- **Frontend/backend error-handling regression**: the exact "footer-only feedback" bug fixed in `ingestion.js` earlier this project still exists, unfixed, in `ruleBuilder.js`, `ruleTesting.js`, and `tuning.js` — none of the three render an in-body error box on a failed primary action.

## 10. Recommended architecture (incremental, not a rewrite)

The existing seams are worth keeping. Concretely, in priority order:

1. **Introduce a canonical `Detection` record** (Phase 2) as a new type layered on top of — not replacing — the existing Detection Candidate. Candidates still come from behavior modules; a `Detection` wraps a candidate plus lifecycle/version/test-case/quality-score fields. This is additive, not a rewrite of `detection-engine/`.
2. **Give `rule-generation/` a shared condition→clause IR** before adding the CIDR/DNS/C2 evaluators' new condition shapes (range comparisons, computed scores) — otherwise Phase 3's new evaluators will multiply the existing 5-way duplication rather than fix it.
3. **Fix `ruleTester.js`'s substring-match semantics** before building the positive/negative/edge-case test framework (Phase 5) on top of it — a test framework built on a matcher with this bug will report false confidence.
4. **Route Elasticsearch and `ai/test` errors through the existing central error handler** rather than each route re-implementing its own leaky catch block — small, mechanical, high-value fix.
5. **Extract session-mutation logic out of `routes/api.js`** into `DetectionStore`/`TestResultStore`-style modules (Phase 21) before adding persistence — `pipelineOrchestrator.js` already shows the right pattern; routes should call storage modules, not touch `session.*` directly.
6. **Do not touch**: `ecs-mapping/`, `field-discovery/`, `log-source-id/`, `ai/` — all three audits found these genuinely solid, already-tested, and already exhibiting the target design (explainable output, deterministic-first, graceful fallback). Phases that touch ECS mapping maturity (Phase 7) should extend statuses/reasons, not restructure the mapper.

---

*This document reflects the repository at the commit noted above. It should be revisited after each milestone, not treated as a one-time snapshot.*
