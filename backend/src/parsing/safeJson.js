'use strict';

const config = require('../config/env');

class SafeParseError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SafeParseError';
  }
}

/**
 * Parses a JSON string with defensive limits:
 *  - rejects oversized input before calling JSON.parse
 *  - rejects excessive nesting depth (defends against crafted deeply-nested payloads)
 *  - never uses eval / Function / vm - only JSON.parse
 */
function safeJsonParse(text, { maxBytes = config.upload.maxPasteBytes, maxDepth = 50 } = {}) {
  if (typeof text !== 'string') {
    throw new SafeParseError('Input must be a string');
  }
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new SafeParseError(`Input exceeds maximum allowed size of ${maxBytes} bytes`);
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new SafeParseError(`Invalid JSON: ${err.message}`);
  }

  assertDepth(parsed, maxDepth);
  return parsed;
}

function assertDepth(value, maxDepth, depth = 0) {
  if (depth > maxDepth) {
    throw new SafeParseError(`JSON nesting exceeds maximum depth of ${maxDepth}`);
  }
  if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      assertDepth(value[key], maxDepth, depth + 1);
    }
  }
}

module.exports = { safeJsonParse, SafeParseError };
