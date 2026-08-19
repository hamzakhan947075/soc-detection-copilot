# Production Maturity Assessment

Last verified: 2026-08-19, after adding AI-suggested detections on top of
Milestone 14 (commit `3f86aa6` plus the AI-suggested-detections feature and
its tests added on top of it).

This document is deterministic, not a subjective score: every line below
is either a command you can re-run yourself or a specific file/line
reference, not an opinion. Where something is a deliberate scope boundary
rather than a bug, it's labeled as such - this project does not claim to
be "production ready" in the generic sense, because that phrase depends
entirely on what you're deploying it for. See
[Known limitations](README.md#known-limitations-stated-honestly-not-hidden)
for the full, honest list this document summarizes.

## How to re-verify this yourself

```bash
cd backend && npm test && npm run lint && npm audit --audit-level=high
cd ../frontend && npm test && npm audit --audit-level=high
cd ../e2e && npm install && npx playwright install --with-deps chromium && npm test
```

All commands pass as of the date above. CI (`.github/workflows/ci.yml`)
runs the same checks, plus a boot smoke test, on every push/PR to `main`
on Node 18.x and 20.x.

## Testing

| Fact | Status |
|---|---|
| Backend unit/integration tests | 327 passing, 0 failing (`cd backend && npm test`) |
| Frontend unit tests | 39 passing, 0 failing (`cd frontend && npm test`) |
| End-to-end tests (real Chromium) | 8 passing, 0 failing (`cd e2e && npm test`) - full pipeline golden path, opt-in-auth login/logout, AI-suggested detections against a stubbed real AI provider, and 3 frontend error paths, each driven against a real running backend |
| Backend lint | 0 errors, 0 warnings (`cd backend && npm run lint`) |
| Backend/frontend/e2e dependency audits | 0 vulnerabilities at any severity, all three `package.json`s |
| CI | 5 jobs (lint+test, frontend-test, e2e-test, security-audit, boot-smoke-test), each on Node 18.x and 20.x where applicable |
| Browser/E2E test coverage | **Real but not exhaustive.** The golden path (ingest → ECS map → detect → generate/test a rule → export a report) and the auth login/logout flow are covered end-to-end in a real browser. Most individual tab interactions and edge cases beyond that are still only verified by hand, not by an automated test. |
| Test-case framework scope | Auto-generated positive/negative/edge cases prove a rule matches what it *claims* to match - they cannot prove real-world attacker-variation coverage. This is a property of static rule testing in general, not an implementation shortfall. |

## Security

| Control | Where |
|---|---|
| Prototype-pollution guard (CWE-1321) | `backend/src/utils/safePath.js`, applied at the ECS-mapping API boundary and in both internal `setPath` implementations |
| SSRF guard on custom AI provider URLs | `backend/src/ai/aiConfigStore.js` - blocks cloud metadata addresses, allows loopback/private ranges (needed for self-hosted LLMs) |
| XSS: HTML-escaping of externally-derived text | `frontend/js/utils.js`'s `escapeHtml`, applied at every `innerHTML` interpolation of API/log-derived text across all 13 tabs and the login screen (audited end-to-end in Milestone 13; one real gap - the login error path - was found and fixed) |
| Upload validation | Extension allowlist, size limit, MIME sanity check (`backend/src/ingestion/upload.js`); nothing uploaded is ever executed |
| Bounded JSON parsing | `backend/src/parsing/safeJson.js` - size- and depth-bounded before `JSON.parse`, never `eval` |
| Outbound request timeouts | Every AI provider call and every Elasticsearch call has a request timeout; AI calls additionally retry transient failures (network error, 429, 5xx) with backoff, never retrying auth errors |
| Rate limiting, security headers, generic error responses | `helmet`, `express-rate-limit`, `backend/src/security/middleware.js` |
| `child_process`/shell execution | None anywhere in the codebase - there is no command-injection surface |
| Authentication | Opt-in, single shared password (`APP_PASSWORD`) - see the scope note below |

## Persistence & session model

| Fact | Status |
|---|---|
| Detection lifecycle (draft → ... → production) | Durable - SQLite (`backend/src/persistence/`), keyed by evaluator id, survives a restart |
| Everything else (parsed events, mappings, normalized events, in-session detections/rules/test results) | **In-memory only, 2-hour TTL.** Does not survive a restart. This is a deliberate single-analyst-workspace design, not a bug - see `ARCHITECTURE.md`'s "Session model" section |
| SQLite file durability on a specific host | Depends on the host's filesystem persistence (e.g. Render's free tier filesystem is ephemeral across deploys unless the DB path is on a mounted disk) |

## Authentication - explicit scope boundary

Real, tested, and live-verified - but deliberately minimal:

- One shared password, not per-analyst accounts. No username, no per-user audit trail beyond a free-text `author` field callers set themselves.
- No server-side session table, so no way to revoke one session early - only `SESSION_SECRET` rotation (invalidates every session, including the caller's own) or the 12-hour TTL.
- This is the right scope for a single-analyst tool. It is the **wrong** scope for a multi-user SOC team sharing one deployment - that would need real per-user accounts, which this project does not have and was never scoped to build.

## AI-suggested detections - the one deliberate exception to deterministic-first

Every other AI feature in this app is narrative-only and cannot alter a
detection, mapping, rule, or lifecycle status - see
[ARCHITECTURE.md](ARCHITECTURE.md#why-deterministic-first). AI-suggested
detections (`POST /sessions/:id/detect/ai-suggested`) are the sole,
deliberate exception: an analyst can opt in to having AI propose additional
detection candidates from a real sample of this session's normalized data.

- **Additive, not a replacement.** The deterministic behavior catalog is
  completely unaffected; this is a separate, explicitly-triggered action,
  and the app works identically with no AI key configured (the route 400s
  with a clear `ai_not_configured` code instead of silently doing nothing).
- **Two deterministic gates before anything reaches a session**, both
  covered by real tests (`backend/tests/aiDetectionSuggestor.test.js`,
  `e2e/tests/ai-detections.spec.js`): field/shape validation against the
  real ECS fields present in the dataset (a hallucinated field gets that
  condition dropped, not substituted), and re-evaluation of every surviving
  candidate's conditions against the real normalized events with the same
  matcher (`testing/ruleTester.js`) every generated rule is tested with - a
  candidate that doesn't actually match a real event is dropped.
- **Always visibly labeled** - a "✨ AI-suggested" badge in the UI
  (`frontend/js/tabs/detection.js`), `source: 'ai'` on the underlying
  object - never presented as indistinguishable from a deterministic
  behavior-catalog detection.
- **What it can't do**: prove a real, matching pattern is actually
  malicious rather than coincidental - only that the pattern genuinely
  exists in the data. It's a hypothesis-generation aid, not a decision.

## Frontend

- 39 unit tests cover the pure/testable layer (`escapeHtml` and badge helpers, `state.js`'s `resolveStage()`, `api.js`'s error-handling contract, `pipelineBar.js`'s stage classification).
- 8 real-browser E2E tests (`e2e/`, Playwright + Chromium) cover the golden path, the auth login/logout flow, and AI-suggested detections against a stubbed real AI provider, all against a real running backend - not a mock, not jsdom.
- All 13 tab modules now show an in-body error box on a failed API call (audited and closed in Milestone 13 - 7 of 13 were missing it before).
- No frontend build step, no bundler, no framework - by design, not as a gap to fill later.

## What this project deliberately is not

- **Not a multi-tenant SaaS product.** Single-analyst workspace, in-memory session state, single shared password.
- **Not a SIEM.** It does not ingest live streams, store historical data at scale, or execute the queries it generates - `rule-validation/` validates query syntax, it never runs a query against a live system.
- **Not a replacement for analyst judgment on ECS mapping or MITRE mapping.** Both are confidence-scored heuristics; the UI always shows the confidence and reasoning and never presents an uncertain mapping as definitive.
- **Not exhaustive attack coverage.** DNS-tunneling entropy, C2-beaconing timing regularity, and CIDR internal/external comparison are real, tested, deterministic signals - but their *generated query* can only assert "field exists" for the first two, because entropy and multi-event timing regularity cannot be expressed as a static filter in KQL/EQL/ES|QL/Lucene/Sigma. This is a property of static query languages, documented inline in `backend/src/detection-engine/behaviors/networkBehaviors.js`.

## If you were taking this to a real multi-analyst production deployment

In priority order, the gaps that would actually matter:

1. Per-analyst accounts and an audit trail tied to a real identity, not opt-in single-password auth.
2. Broader browser/E2E coverage of the 13 tab modules' individual interactions and edge cases - today's `e2e/` suite proves the golden path and the auth flow work in a real browser, but doesn't attempt exhaustive per-tab coverage.
3. Durable session/pipeline state (a real datastore), not 2-hour in-memory TTL, if more than one analyst needs to share in-progress work.
4. A qualified security review of the generated detection rules' real-world coverage - the built-in test-case framework can only prove internal consistency, not attacker-variation coverage.

None of these are secretly broken today; they are scope boundaries this
project was never built past. Closing #1 was this project's Milestone 11;
#2 went from zero frontend tests to 39 unit tests plus an 8-test real-browser
E2E suite covering the golden path, auth flow, and AI-suggested detections.
