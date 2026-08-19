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
    res.status(400).json({ error: err.message });
    return;
  }
  if (err && err.name === 'MulterError') {
    res.status(400).json({ error: `Upload rejected: ${err.message}` });
    return;
  }
  // eslint-disable-next-line no-console
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'An internal error occurred while processing the request.' });
}

module.exports = { securityHeaders, apiRateLimiter, errorHandler };
