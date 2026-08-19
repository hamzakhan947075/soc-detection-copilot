'use strict';

const { safeJsonParse } = require('./safeJson');

/**
 * Deterministically detects the raw log format from its content (not just the
 * file extension, since analysts often rename or paste content directly).
 * Returns one of: 'json-array', 'ndjson', 'csv', 'plain'
 */
function detectFormat(rawText, filenameHint = '') {
  const trimmed = rawText.trim();
  if (!trimmed) {
    return { format: 'plain', reason: 'Empty input' };
  }

  const ext = (filenameHint.match(/\.[a-z0-9]+$/i) || [''])[0].toLowerCase();

  // Try a single JSON document (array or object) first.
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    try {
      const parsed = safeJsonParse(trimmed);
      if (Array.isArray(parsed)) {
        return { format: 'json-array', reason: 'Content parses as a single JSON array of events' };
      }
      if (typeof parsed === 'object' && parsed !== null) {
        // A single JSON object could still be one Elastic event.
        return { format: 'json-array', reason: 'Content parses as a single JSON object (treated as one event)' };
      }
    } catch (_err) {
      // fall through to NDJSON / other checks
    }
  }

  // NDJSON / JSONL: multiple lines, each independently valid JSON. A
  // dataset is still treated as ndjson even if a minority of lines are
  // corrupted/truncated (common in real exports) as long as most of a
  // sample parse cleanly and the first line does.
  const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length > 0) {
    const sampleSize = Math.min(lines.length, 25);
    let validJsonLines = 0;
    let firstLineValid = false;
    for (let i = 0; i < sampleSize; i++) {
      try {
        safeJsonParse(lines[i]);
        validJsonLines++;
        if (i === 0) firstLineValid = true;
      } catch (_err) {
        // not JSON on this line
      }
    }
    if (firstLineValid && validJsonLines / sampleSize >= 0.6) {
      return { format: 'ndjson', reason: 'Most sampled lines parse as independent JSON objects' };
    }
  }

  // CSV: consistent delimiter count across the header + first data rows.
  if (ext === '.csv' || looksLikeCsv(lines)) {
    return { format: 'csv', reason: 'Consistent comma-delimited columns detected across sampled lines' };
  }

  return { format: 'plain', reason: 'Content treated as unstructured plain-text log lines (e.g. syslog)' };
}

function looksLikeCsv(lines) {
  if (lines.length < 2) return false;
  const sample = lines.slice(0, Math.min(lines.length, 10));
  const counts = sample.map((l) => splitCsvLine(l).length);
  const first = counts[0];
  if (first < 2) return false;
  return counts.every((c) => c === first);
}

/** Minimal CSV line splitter that respects double-quoted fields. */
function splitCsvLine(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      fields.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

module.exports = { detectFormat, splitCsvLine };
