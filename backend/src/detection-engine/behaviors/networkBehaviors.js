'use strict';

const { makeCandidate } = require('../candidateFactory');
const { groupBy, maxEventsInWindow, shannonEntropy } = require('../utils');

const ONE_MIN_MS = 60 * 1000;
const HIGH_ENTROPY_THRESHOLD = 3.8;
const LONG_LABEL_THRESHOLD = 35;

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
  const candidates = [];
  const suspicious = dnsEvents.filter((e) => {
    const name = String(e.flat['dns.question.name'] || '');
    const label = name.split('.')[0] || '';
    return label.length >= LONG_LABEL_THRESHOLD && shannonEntropy(label) >= HIGH_ENTROPY_THRESHOLD;
  });

  if (suspicious.length === 0) return candidates;

  const byDomain = groupBy(suspicious, (e) => {
    const parts = String(e.flat['dns.question.name']).split('.');
    return parts.slice(-2).join('.');
  });

  for (const [domain, group] of byDomain.entries()) {
    if (group.length < 3) continue;
    candidates.push(
      makeCandidate({
        name: 'Possible DNS Tunneling',
        category: 'network',
        severity: 'medium',
        confidence: 0.6,
        description: `${group.length} DNS queries with long, high-entropy subdomains observed under "${domain}" - one heuristic signal for DNS tunneling/exfiltration. Confirm with payload/volume analysis before treating as confirmed.`,
        requiredFields: ['dns.question.name', 'source.ip', '@timestamp'],
        mitreHint: 'dns_tunneling',
        matchedEventIndexes: group.map((e) => e.index),
        evidence: group.slice(0, 5).map((e) => String(e.flat['dns.question.name'])),
        // The actual signal is subdomain length + entropy, which the simple
        // condition model can't express; the rendered query only checks
        // that a DNS question exists and should be refined by the analyst
        // (e.g. with a length() function in Elastic) before deployment.
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
      ruleConditions: [{ field: 'destination.port', values: ['4444', '1337', '6666', '31337', '8081', '8888'] }],
    })
  );
  return candidates;
}

function detectBeaconing(events) {
  const withDest = events.filter((e) => e.flat['destination.ip'] && e.timestampMs);
  const byPair = groupBy(withDest, (e) => `${e.flat['source.ip']}->${e.flat['destination.ip']}`);
  const candidates = [];

  for (const [pair, group] of byPair.entries()) {
    if (group.length < 6) continue;
    const timestamps = group.map((e) => e.timestampMs).sort((a, b) => a - b);
    const intervals = [];
    for (let i = 1; i < timestamps.length; i++) intervals.push(timestamps[i] - timestamps[i - 1]);
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (mean <= 0) continue;
    const variance = intervals.reduce((sum, v) => sum + (v - mean) ** 2, 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    const coefficientOfVariation = stdDev / mean;

    // Low variance in inter-connection timing is the classic beaconing signal.
    if (coefficientOfVariation < 0.15 && mean < 30 * ONE_MIN_MS) {
      candidates.push(
        makeCandidate({
          name: 'Possible C2 Beaconing',
          category: 'network',
          severity: 'high',
          confidence: 0.65,
          description: `Connections from ${pair} occur at highly regular intervals (avg ${Math.round(mean / 1000)}s, coefficient of variation ${coefficientOfVariation.toFixed(2)}) - a common beaconing pattern for command-and-control check-ins.`,
          requiredFields: ['source.ip', 'destination.ip', '@timestamp'],
          mitreHint: 'c2_communication',
          matchedEventIndexes: group.map((e) => e.index),
          evidence: [`pair=${pair}`, `connections=${group.length}`, `avg_interval_sec=${Math.round(mean / 1000)}`],
          // The actual signal is inter-connection timing regularity, which
          // the simple condition model can't express; the rendered query
          // only checks that a destination exists and should be refined
          // (e.g. with a scheduled timing analysis) before deployment.
          ruleConditions: [{ field: 'destination.ip', exists: true }],
        })
      );
    }
  }
  return candidates;
}

module.exports = { detectNetworkBehaviors };
