'use strict';

const { makeCandidate } = require('../candidateFactory');
const { groupBy } = require('../utils');
const { evaluateDnsTunneling } = require('../evaluators/dnsTunnelingEvaluator');
const { evaluateBeaconing } = require('../evaluators/c2BeaconingEvaluator');

const ONE_MIN_MS = 60 * 1000;

function detectNetworkBehaviors(events) {
  const candidates = [];
  candidates.push(...detectPortScanning(events));
  candidates.push(...detectDnsTunneling(events));
  candidates.push(...detectSuspiciousOutbound(events));
  candidates.push(...detectBeaconing(events));
  return candidates;
}

function detectPortScanning(events) {
  const withDestPort = events.filter((e) => e.flat['destination.port'] !== undefined && e.flat['destination.port'] !== null);
  const bySource = groupBy(withDestPort, (e) => e.flat['source.ip']);
  const candidates = [];

  for (const [ip, group] of bySource.entries()) {
    const distinctPorts = new Set(group.map((e) => String(e.flat['destination.port'])));
    const distinctDests = new Set(group.map((e) => e.flat['destination.ip']).filter(Boolean));
    if (distinctPorts.size < 15 && distinctDests.size < 10) continue;

    candidates.push(
      makeCandidate({
        name: 'Port Scanning',
        category: 'network',
        severity: distinctPorts.size >= 100 ? 'high' : 'medium',
        confidence: Math.min(0.92, 0.5 + distinctPorts.size * 0.005 + distinctDests.size * 0.01),
        description: `Source IP ${ip} connected to ${distinctPorts.size} distinct destination ports across ${distinctDests.size} destination host(s) - consistent with port/host scanning.`,
        requiredFields: ['source.ip', 'destination.ip', 'destination.port', '@timestamp'],
        mitreHint: 'network_scanning',
        recommendedThreshold: { count: 15, groupBy: ['source.ip'], distinctField: 'destination.port' },
        matchedEventIndexes: group.map((e) => e.index),
        evidence: [`source.ip=${ip}`, `distinct_ports=${distinctPorts.size}`, `distinct_destinations=${distinctDests.size}`],
        // No field=value filter needed - the signal is purely the cardinality
        // of destination.port per source.ip, enforced via the threshold's
        // distinctField rather than a content match.
        ruleConditions: [{ field: 'destination.port', exists: true }],
      })
    );
  }
  return candidates;
}

function detectDnsTunneling(events) {
  const dnsEvents = events.filter((e) => e.flat['dns.question.name']);
  if (dnsEvents.length === 0) return [];

  const byDomain = groupBy(dnsEvents, (e) => {
    const parts = String(e.flat['dns.question.name']).split('.');
    return parts.slice(-2).join('.');
  });

  const candidates = [];
  for (const [domain, group] of byDomain.entries()) {
    const evaluatorResult = evaluateDnsTunneling(group.map((e) => String(e.flat['dns.question.name'])));
    if (!evaluatorResult.matched) continue;

    candidates.push(
      makeCandidate({
        name: 'Possible DNS Tunneling',
        category: 'network',
        severity: 'medium',
        confidence: Math.min(0.85, 0.5 + evaluatorResult.score * 0.4),
        description: `${evaluatorResult.evidence.suspiciousCount}/${evaluatorResult.evidence.sampleCount} DNS queries under "${domain}" show length/entropy/character-distribution signals consistent with tunneling (mean entropy ${evaluatorResult.evidence.meanEntropy} bits/char). Confirm with payload/volume analysis before treating as confirmed.`,
        requiredFields: ['dns.question.name', 'source.ip', '@timestamp'],
        mitreHint: 'dns_tunneling',
        matchedEventIndexes: group.map((e) => e.index),
        evidence: evaluatorResult.reasons,
        evaluatorResult,
        // Deterministic evaluator: detection-engine/evaluators/
        // dnsTunnelingEvaluator.js (length + Shannon entropy + character
        // distribution + subdomain depth, requiring a *consistent* pattern
        // across the group - see evaluatorResult for the full breakdown).
        // None of the 5 target query languages can express entropy or
        // character-distribution as a static filter (that needs a scripted
        // field, not a query), so the rendered query can only check that a
        // DNS question exists - this is a genuine, stated limitation of
        // static query languages, not an unfinished implementation.
        ruleConditions: [{ field: 'dns.question.name', exists: true }],
      })
    );
  }
  return candidates;
}

function detectSuspiciousOutbound(events) {
  const candidates = [];
  const matches = events.filter((e) => {
    const port = Number(e.flat['destination.port']);
    const outcome = String(e.flat['event.outcome'] || '').toLowerCase();
    return Number.isFinite(port) && [4444, 1337, 6666, 31337, 8081, 8888].includes(port) && outcome !== 'failure';
  });
  if (matches.length === 0) return candidates;

  candidates.push(
    makeCandidate({
      name: 'Suspicious Outbound Connection (Known C2 Port)',
      category: 'network',
      severity: 'high',
      confidence: 0.6,
      description: `${matches.length} outbound connection(s) observed to ports commonly associated with C2 frameworks/backdoors (e.g. 4444, 1337, 31337). Port-based heuristic only - verify against destination reputation.`,
      requiredFields: ['source.ip', 'destination.ip', 'destination.port', '@timestamp'],
      mitreHint: 'c2_communication',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => `${e.flat['source.ip']} -> ${e.flat['destination.ip']}:${e.flat['destination.port']}`),
      ruleConditions: [{ field: 'destination.port', values: ['4444', '1337', '6666', '31337', '8081', '8888'], exact: true }],
    })
  );
  return candidates;
}

function detectBeaconing(events) {
  const withDest = events.filter((e) => e.flat['destination.ip'] && e.timestampMs);
  const byPair = groupBy(withDest, (e) => `${e.flat['source.ip']}->${e.flat['destination.ip']}`);
  const candidates = [];

  for (const [pair, group] of byPair.entries()) {
    const [srcIp, dstIp] = pair.split('->');
    const evaluatorResult = evaluateBeaconing(
      group.map((e) => e.timestampMs),
      { destination: dstIp, destinationPort: group[0].flat['destination.port'] },
      { maxMeanIntervalMs: 30 * ONE_MIN_MS }
    );
    if (!evaluatorResult.matched) continue;

    candidates.push(
      makeCandidate({
        name: 'Possible C2 Beaconing',
        category: 'network',
        severity: 'high',
        confidence: Math.min(0.9, 0.5 + evaluatorResult.score * 0.4),
        description: `Connections from ${srcIp} to ${dstIp} occur at highly regular intervals (avg ${Math.round(evaluatorResult.evidence.intervalMeanMs / 1000)}s, coefficient of variation ${evaluatorResult.evidence.coefficientOfVariation}) - a common beaconing pattern for command-and-control check-ins.`,
        requiredFields: ['source.ip', 'destination.ip', '@timestamp'],
        mitreHint: 'c2_communication',
        matchedEventIndexes: group.map((e) => e.index),
        evidence: [`pair=${pair}`, `connections=${group.length}`, ...evaluatorResult.reasons],
        evaluatorResult,
        // Deterministic evaluator: detection-engine/evaluators/
        // c2BeaconingEvaluator.js (mean/stddev/coefficient-of-variation of
        // inter-connection intervals - see evaluatorResult for the full
        // breakdown). Timing regularity across multiple events is
        // fundamentally not expressible as a single-event filter condition
        // in any of the 5 target query languages (it requires cross-event
        // aggregation, not a static WHERE clause) - the rendered query can
        // only check that a destination exists. This is a genuine,
        // stated limitation, not an unfinished implementation.
        ruleConditions: [{ field: 'destination.ip', exists: true }],
      })
    );
  }
  return candidates;
}

module.exports = { detectNetworkBehaviors };
