'use strict';

const { flattenEvent } = require('../field-discovery/flatten');
const { extractPrimaryMessage } = require('../parsing/parsers');
const { toEpochMs } = require('./utils');
const { mapToMitre } = require('../mitre/mitreMap');

const { detectAuthBehaviors } = require('./behaviors/authBehaviors');
const { detectLinuxBehaviors } = require('./behaviors/linuxBehaviors');
const { detectWindowsBehaviors } = require('./behaviors/windowsBehaviors');
const { detectNetworkBehaviors } = require('./behaviors/networkBehaviors');
const { detectWebBehaviors } = require('./behaviors/webBehaviors');
const { detectFirewallBehaviors } = require('./behaviors/firewallBehaviors');

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Builds the "enriched event" view every behavior module consumes: the
 * normalized ECS event, flattened for easy dotted-path lookups, plus the
 * best-effort primary message and a resolved epoch timestamp.
 */
function enrichEvents(normalizedEvents) {
  return normalizedEvents.map((normalized, index) => {
    const flat = flattenEvent(normalized);
    return {
      index,
      normalized,
      flat,
      message: extractPrimaryMessage(normalized) || String(flat.message || ''),
      timestampMs: toEpochMs(flat['@timestamp']),
    };
  });
}

/**
 * Runs every detection behavior module against the normalized event set and
 * returns a ranked list of Detection Candidates with MITRE mapping attached.
 */
function runDetectionEngine(normalizedEvents) {
  const events = enrichEvents(normalizedEvents);

  const raw = [
    ...detectAuthBehaviors(events),
    ...detectLinuxBehaviors(events),
    ...detectWindowsBehaviors(events),
    ...detectNetworkBehaviors(events),
    ...detectWebBehaviors(events),
    ...detectFirewallBehaviors(events),
  ];

  const withMitre = raw.map((candidate) => ({
    ...candidate,
    mitre: mapToMitre(candidate.mitreHint),
  }));

  withMitre.sort((a, b) => {
    const sevDiff = (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;
    return b.confidence - a.confidence;
  });

  return {
    totalEventsAnalyzed: events.length,
    detectionCount: withMitre.length,
    detections: withMitre,
  };
}

module.exports = { runDetectionEngine, enrichEvents };
