'use strict';

const crypto = require('crypto');

/**
 * Structured request logging: one JSON line per request to stdout, with a
 * request_id an operator can grep across a log aggregator. Deliberately
 * logs metadata only - method, route (query string stripped), status,
 * duration, and (when available) the session's pipeline stage - never a
 * request body, so there is no code path by which an API key, password, or
 * raw log content ever reaches a log line. errorHandler (security/
 * middleware.js) attaches its own already-sanitized error message to
 * res.locals.errorMessage before responding; this only ever surfaces that
 * same, already-safe text, never the original unhandled error.
 */
function requestLogger() {
  return (req, res, next) => {
    const requestId = crypto.randomUUID();
    req.requestId = requestId;
    const startedAtNs = process.hrtime.bigint();
    res.setHeader('X-Request-Id', requestId);

    res.on('finish', () => {
      const durationMs = Number(process.hrtime.bigint() - startedAtNs) / 1e6;
      const logLine = {
        request_id: requestId,
        timestamp: new Date().toISOString(),
        method: req.method,
        route: (req.originalUrl || req.url || '').split('?')[0],
        status: res.statusCode,
        duration_ms: Math.round(durationMs * 100) / 100,
        pipeline_stage: (req.session && req.session.stage) || undefined,
        error: res.locals.errorMessage || undefined,
      };
      console.log(JSON.stringify(logLine));
    });

    next();
  };
}

module.exports = { requestLogger };
