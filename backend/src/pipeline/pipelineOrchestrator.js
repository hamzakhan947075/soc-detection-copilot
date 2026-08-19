'use strict';

const { parseRawLogs } = require('../parsing/parsers');
const { discoverFields } = require('../field-discovery/fieldDiscovery');
const { identifyLogSource } = require('../log-source-id/sourceIdentifier');
const { normalizeEvent } = require('../normalization/normalizer');
const { ECS_FIELDS } = require('../ecs-mapping/ecsSchema');

/** Stage ①②③ - ingest raw text, detect format, parse, discover fields, identify source. */
function ingest(rawText, filenameHint) {
  const parsed = parseRawLogs(rawText, filenameHint);
  const fieldDiscovery = discoverFields(parsed.events);
  const logSource = identifyLogSource(parsed.events, filenameHint);

  return {
    format: parsed.format,
    formatReason: parsed.formatReason,
    totalParsed: parsed.totalParsed,
    truncated: parsed.truncated,
    events: parsed.events,
    fieldDiscovery,
    logSource,
  };
}

/** Builds the default (suggested) mapping set from field discovery, before any analyst overrides. */
function defaultMappings(fieldDiscovery) {
  return fieldDiscovery.fields
    .filter((f) => f.ecsCandidate)
    .map((f) => ({
      rawField: f.field,
      ecsField: f.ecsCandidate,
      ecsType: (ECS_FIELDS[f.ecsCandidate] && ECS_FIELDS[f.ecsCandidate].type) || 'keyword',
      confidence: f.ecsConfidence,
      status: f.ecsStatus,
    }));
}

/** Stage ④⑤ - apply approved mappings to every event, producing normalized ECS events. */
function normalizeAll(events, mappings) {
  const normalizedEvents = [];
  const sampleChanges = [];
  let totalChanges = 0;

  events.forEach((rawEvent, idx) => {
    const { normalized, changes, unmapped } = normalizeEvent(rawEvent, mappings);
    normalizedEvents.push(normalized);
    totalChanges += changes.length;
    if (idx < 10) sampleChanges.push({ index: idx, raw: rawEvent, normalized, changes, unmapped });
  });

  const mappedFieldCount = mappings.filter((m) => m.ecsField).length;
  const totalFieldCount = mappings.length || 1;
  const coveragePercent = Math.round((mappedFieldCount / totalFieldCount) * 10000) / 100;

  return { normalizedEvents, sampleChanges, coveragePercent, totalChanges };
}

module.exports = { ingest, defaultMappings, normalizeAll };
