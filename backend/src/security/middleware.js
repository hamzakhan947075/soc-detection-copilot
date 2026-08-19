'use strict';

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('../config/env');
const { SafeParseError } = require('../parsing/safeJson');
const { UploadValidationError } = require('../ingestion/upload');

function securityHeaders() {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  });
}

function apiRateLimiter() {
  return rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please slow down and try again shortly.' },
  });
}

/**
 * Central error handler. Never reflects internal error details (stack
 * traces, file paths, library internals) back to the client - only a safe,
 * generic message plus a category derived from known error types.
 */
function errorHandler(err, _req, res, _next) {
  if (err instanceof SafeParseError || err instanceof UploadValidationError) {
    res.locals.errorMessage = err.message;
    res.status(400).json({ error: err.message });
    return;
  }
  if (err && err.name === 'MulterError') {
    const message = `Upload rejected: ${err.message}`;
    res.locals.errorMessage = message;
    res.status(400).json({ error: message });
    return;
  }
  console.error('Unhandled error:', err);
  // observability/requestLogger.js's request-completion log line picks up
  // res.locals.errorMessage - this is deliberately the same safe, generic
  // text sent to the client, never the raw err/stack logged just above.
  res.locals.errorMessage = 'Internal error';
  res.status(500).json({ error: 'An internal error occurred while processing the request.' });
}

module.exports = { securityHeaders, apiRateLimiter, errorHandler };
