'use strict';

const { safeJsonParse, SafeParseError } = require('./safeJson');
const { detectFormat, splitCsvLine } = require('./formatDetector');
const config = require('../config/env');

/**
 * Parses raw text (in whatever format) into an array of plain-object "events".
 * Every event keeps its original nested structure where possible (Elastic
 * exports are frequently nested, e.g. host.name, event.dataset) - flattening
 * happens later in field-discovery, not here.
 */
function parseRawLogs(rawText, filenameHint = '') {
  const detection = detectFormat(rawText, filenameHint);
  const events = parseByFormat(rawText, detection.format);
  const capped = events.slice(0, config.upload.maxEventsPerDataset);
  return {
    format: detection.format,
    formatReason: detection.reason,
    totalParsed: events.length,
    truncated: events.length > capped.length,
    events: capped,
  };
}

function parseByFormat(rawText, format) {
  switch (format) {
    case 'json-array':
      return parseJsonArray(rawText);
    case 'ndjson':
      return parseNdjson(rawText);
    case 'csv':
      return parseCsv(rawText);
    case 'plain':
    default:
      return parsePlainText(rawText);
  }
}

function parseJsonArray(rawText) {
  const parsed = safeJsonParse(rawText.trim());
  if (Array.isArray(parsed)) {
    return parsed.map((e) => (typeof e === 'object' && e !== null ? e : { message: String(e) }));
  }
  return [parsed];
}

function parseNdjson(rawText) {
  const lines = rawText.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const events = [];
  for (const line of lines) {
    try {
      const parsed = safeJsonParse(line);
      events.push(typeof parsed === 'object' && parsed !== null ? parsed : { message: String(parsed) });
    } catch (err) {
      // Skip unparseable lines but keep them visible as a raw-message fallback
      // so no data is silently discarded.
      if (err instanceof SafeParseError) {
        events.push({ message: line, _parseWarning: 'Line was not valid JSON' });
      }
    }
  }
  return events;
}

function parseCsv(rawText) {
  const lines = rawText.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length === 0) return [];
  const header = splitCsvLine(lines[0]).map((h) => h.trim());
  const events = [];
  for (let i = 1; i < lines.length; i++) {
    const fields = splitCsvLine(lines[i]);
    const event = {};
    header.forEach((col, idx) => {
      event[col || `column_${idx}`] = fields[idx] !== undefined ? fields[idx] : '';
    });
    events.push(event);
  }
  return events;
}

function parsePlainText(rawText) {
  const lines = rawText.split(/\r?\n/).filter((l) => l.trim().length > 0);
  return lines.map((line) => ({ message: line }));
}

/**
 * Elastic exports frequently hide the actually useful text inside one of
 * `message`, `event.original`, or `log.original`. This extracts the best
 * candidate for downstream free-text analysis (e.g. sshd auth lines).
 */
function extractPrimaryMessage(event) {
  if (typeof event !== 'object' || event === null) return String(event);
  if (typeof event.message === 'string' && event.message.trim()) return event.message;
  if (event.event && typeof event.event.original === 'string' && event.event.original.trim()) {
    return event.event.original;
  }
  if (event.log && typeof event.log.original === 'string' && event.log.original.trim()) {
    return event.log.original;
  }
  return '';
}

module.exports = { parseRawLogs, extractPrimaryMessage };
