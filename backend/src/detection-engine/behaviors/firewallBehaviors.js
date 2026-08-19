'use strict';

const { makeCandidate } = require('../candidateFactory');
const { groupBy } = require('../utils');
const { evaluateCidrDirection, DEFAULT_INTERNAL_CIDRS } = require('../evaluators/cidrEvaluator');
const config = require('../../config/env');

const INTERNAL_CIDRS = config.internalCidrRanges && config.internalCidrRanges.length ? config.internalCidrRanges : DEFAULT_INTERNAL_CIDRS;

function detectFirewallBehaviors(events) {
  const firewallEvents = events.filter((e) => e.flat['destination.ip'] && (e.flat['event.action'] || e.flat['event.outcome']));
  if (firewallEvents.length === 0) return [];

  const candidates = [];
  candidates.push(...detectRepeatedDenies(firewallEvents));
  candidates.push(...detectInternalToExternalAnomalies(firewallEvents));
  candidates.push(...detectSuspiciousDestinations(firewallEvents));
  return candidates;
}

function isDenied(e) {
  const action = String(e.flat['event.action'] || '').toLowerCase();
  const outcome = String(e.flat['event.outcome'] || '').toLowerCase();
  return action.includes('den') || action.includes('block') || action.includes('drop') || outcome === 'failure';
}

function detectRepeatedDenies(events) {
  const denies = events.filter(isDenied);
  const bySource = groupBy(denies, (e) => e.flat['source.ip']);
  const candidates = [];

  for (const [ip, group] of bySource.entries()) {
    if (group.length < 10) continue;
    const distinctDests = new Set(group.map((e) => e.flat['destination.ip']).filter(Boolean));
    candidates.push(
      makeCandidate({
        name: 'Repeated Denied Firewall Connections',
        category: 'firewall',
        severity: group.length >= 50 ? 'high' : 'medium',
        confidence: Math.min(0.9, 0.5 + group.length * 0.01),
        description: `Source IP ${ip} generated ${group.length} denied/blocked connection attempts across ${distinctDests.size} destination(s) - consistent with scanning, misconfiguration, or a blocked attack attempt.`,
        requiredFields: ['source.ip', 'destination.ip', 'event.action', '@timestamp'],
        mitreHint: 'network_scanning',
        recommendedThreshold: { count: 10, groupBy: ['source.ip'] },
        matchedEventIndexes: group.map((e) => e.index),
        evidence: [`source.ip=${ip}`, `denied_count=${group.length}`, `distinct_destinations=${distinctDests.size}`],
        ruleConditions: [{ field: 'event.action', values: ['den', 'block', 'drop'] }],
      })
    );
  }
  return candidates;
}

function detectInternalToExternalAnomalies(events) {
  const matches = events.filter((e) => {
    const src = e.flat['source.ip'];
    const dst = e.flat['destination.ip'];
    if (!src || !dst) return false;
    return evaluateCidrDirection({ sourceIp: src, destinationIp: dst, internalCidrs: INTERNAL_CIDRS, direction: 'internal_source_external_dest' }).matched;
  });

  const byPair = groupBy(matches, (e) => `${e.flat['source.ip']}->${e.flat['destination.ip']}`);
  const candidates = [];
  const highVolumePairs = [...byPair.entries()].filter(([, group]) => group.length >= 20);
  if (highVolumePairs.length === 0) return candidates;

  for (const [pair, group] of highVolumePairs) {
    const [srcIp, dstIp] = pair.split('->');
    const evaluatorResult = evaluateCidrDirection({ sourceIp: srcIp, destinationIp: dstIp, internalCidrs: INTERNAL_CIDRS, direction: 'internal_source_external_dest' });
    candidates.push(
      makeCandidate({
        name: 'Internal-to-External Traffic Anomaly',
        category: 'firewall',
        severity: 'medium',
        confidence: 0.55,
        description: `High-volume internal-to-external connections (${group.length}) observed for ${pair}. Volume-based heuristic only; validate against expected business traffic before treating as malicious.`,
        requiredFields: ['source.ip', 'destination.ip', 'network.bytes', '@timestamp'],
        mitreHint: 'data_exfiltration',
        matchedEventIndexes: group.map((e) => e.index),
        evidence: [`pair=${pair}`, `connections=${group.length}`, ...evaluatorResult.reasons],
        evaluatorResult,
        // Real CIDR evaluation (detection-engine/evaluators/cidrEvaluator.js)
        // against a configurable internal-range list (INTERNAL_CIDR_RANGES
        // env var, default RFC1918 + loopback + link-local). Genuinely
        // expressible in all 5 query languages via the `cidr` condition -
        // see rule-generation/queryLanguages.js.
        ruleConditions: [
          { field: 'source.ip', cidr: { ranges: INTERNAL_CIDRS, mode: 'in' } },
          { field: 'destination.ip', cidr: { ranges: INTERNAL_CIDRS, mode: 'not_in' } },
        ],
      })
    );
  }
  return candidates;
}

function detectSuspiciousDestinations(events) {
  const matches = events.filter((e) => {
    const port = Number(e.flat['destination.port']);
    return Number.isFinite(port) && [4444, 1337, 6666, 31337].includes(port);
  });
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Firewall: Suspicious Destination Port',
      category: 'firewall',
      severity: 'high',
      confidence: 0.6,
      description: `Firewall log entries show traffic to ports commonly associated with malware/C2 (${matches.length} event(s)).`,
      requiredFields: ['source.ip', 'destination.ip', 'destination.port', '@timestamp'],
      mitreHint: 'c2_communication',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => `${e.flat['source.ip']} -> ${e.flat['destination.ip']}:${e.flat['destination.port']}`),
      ruleConditions: [{ field: 'destination.port', values: ['4444', '1337', '6666', '31337'], exact: true }],
    }),
  ];
}

module.exports = { detectFirewallBehaviors };
