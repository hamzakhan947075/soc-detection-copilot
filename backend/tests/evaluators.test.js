'use strict';

const { isIpInCidrList, isInternalIp, isValidIp, evaluateCidrDirection, DEFAULT_INTERNAL_CIDRS } = require('../src/detection-engine/evaluators/cidrEvaluator');
const { scoreDnsQuery, evaluateDnsTunneling } = require('../src/detection-engine/evaluators/dnsTunnelingEvaluator');
const { evaluateBeaconing } = require('../src/detection-engine/evaluators/c2BeaconingEvaluator');

describe('cidrEvaluator', () => {
  test('recognizes RFC1918 IPv4 ranges as internal by default', () => {
    expect(isInternalIp('10.1.2.3')).toBe(true);
    expect(isInternalIp('172.16.5.5')).toBe(true);
    expect(isInternalIp('172.31.255.255')).toBe(true);
    expect(isInternalIp('172.32.0.1')).toBe(false); // just outside the 172.16.0.0/12 range
    expect(isInternalIp('192.168.1.1')).toBe(true);
    expect(isInternalIp('127.0.0.1')).toBe(true);
  });

  test('recognizes a public IPv4 address as external', () => {
    expect(isInternalIp('8.8.8.8')).toBe(false);
    expect(isInternalIp('203.0.113.5')).toBe(false);
  });

  test('handles IPv6 loopback and unique-local ranges', () => {
    expect(isIpInCidrList('::1', DEFAULT_INTERNAL_CIDRS)).toBe(true);
    expect(isIpInCidrList('fd00:1234::1', DEFAULT_INTERNAL_CIDRS)).toBe(true); // fc00::/7 covers fd00::/8
    expect(isIpInCidrList('fe80::1', DEFAULT_INTERNAL_CIDRS)).toBe(true);
  });

  test('recognizes a public IPv6 address as external', () => {
    expect(isIpInCidrList('2001:4860:4860::8888', DEFAULT_INTERNAL_CIDRS)).toBe(false); // Google public DNS
  });

  test('does not cross-match an IPv4 address against an IPv6 range or vice versa', () => {
    expect(isIpInCidrList('10.0.0.1', ['fc00::/7'])).toBe(false);
    expect(isIpInCidrList('fc00::1', ['10.0.0.0/8'])).toBe(false);
  });

  test('honors a custom, configurable CIDR list instead of the default', () => {
    expect(isIpInCidrList('203.0.113.5', ['203.0.113.0/24'])).toBe(true);
    expect(isIpInCidrList('10.0.0.1', ['203.0.113.0/24'])).toBe(false); // no longer internal under the custom list
  });

  test('rejects malformed input without throwing', () => {
    expect(isIpInCidrList('not-an-ip', DEFAULT_INTERNAL_CIDRS)).toBe(false);
    expect(isIpInCidrList('', DEFAULT_INTERNAL_CIDRS)).toBe(false);
    expect(isIpInCidrList(null, DEFAULT_INTERNAL_CIDRS)).toBe(false);
  });

  test('evaluateCidrDirection matches internal-source/external-dest traffic', () => {
    const result = evaluateCidrDirection({ sourceIp: '10.0.0.5', destinationIp: '203.0.113.9', direction: 'internal_source_external_dest' });
    expect(result.matched).toBe(true);
    expect(result.evidence.sourceInternal).toBe(true);
    expect(result.evidence.destinationInternal).toBe(false);
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  test('evaluateCidrDirection does not match two internal endpoints', () => {
    const result = evaluateCidrDirection({ sourceIp: '10.0.0.5', destinationIp: '10.0.0.6', direction: 'internal_source_external_dest' });
    expect(result.matched).toBe(false);
  });

  test('isValidIp distinguishes well-formed addresses from garbage', () => {
    expect(isValidIp('10.0.0.1')).toBe(true);
    expect(isValidIp('::1')).toBe(true);
    expect(isValidIp('not-an-ip')).toBe(false);
    expect(isValidIp('')).toBe(false);
    expect(isValidIp(null)).toBe(false);
    expect(isValidIp('999.999.999.999')).toBe(false);
  });

  test('evaluateCidrDirection supports the reverse direction', () => {
    const result = evaluateCidrDirection({ sourceIp: '203.0.113.9', destinationIp: '10.0.0.5', direction: 'external_source_internal_dest' });
    expect(result.matched).toBe(true);
  });
});

describe('dnsTunnelingEvaluator', () => {
  test('does not flag an ordinary hostname', () => {
    const result = scoreDnsQuery('www.example.com');
    expect(result.suspicious).toBe(false);
  });

  test('flags a long, high-entropy, digit-heavy label as suspicious', () => {
    const encodedLabel = 'x7k2p9qz3mv8w1jr5nt6yb4hc0ld2se9af7gk3pq1z';
    const result = scoreDnsQuery(`${encodedLabel}.exfil.example.net`);
    expect(result.longestLabelLength).toBeGreaterThanOrEqual(35);
    expect(result.suspicious).toBe(true);
    expect(result.reasons.length).toBeGreaterThanOrEqual(2);
  });

  test('evaluateDnsTunneling matches a group that consistently looks encoded', () => {
    const labels = [
      'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
      'z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0',
      'm3n4o5p6q7r8s9t0a1b2c3d4e5f6g7h8i9j0k1l2',
      'q7r8s9t0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
    ].map((l) => `${l}.exfil.example.net`);
    const result = evaluateDnsTunneling(labels);
    expect(result.matched).toBe(true);
    expect(result.evidence.sampleCount).toBe(4);
    expect(result.evidence.suspiciousCount).toBe(4);
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  test('does not match a group with only one unusually long but legitimate-looking hostname', () => {
    const labels = [
      'www.example.com',
      'cdn-assets-eu-west-1-production.example.com', // long but low-entropy, real-looking
      'api.example.com',
      'login.example.com',
    ];
    const result = evaluateDnsTunneling(labels);
    expect(result.matched).toBe(false);
  });

  test('does not match below the minimum group size, even if every sample is suspicious', () => {
    const labels = ['x7k2p9qz3mv8w1jr5nt6yb4hc0ld2se9af7gk3pq1z.exfil.example.net'];
    const result = evaluateDnsTunneling(labels);
    expect(result.matched).toBe(false);
  });
});

describe('c2BeaconingEvaluator', () => {
  test('matches highly regular intervals', () => {
    const base = Date.UTC(2026, 7, 19, 10, 0, 0);
    const timestamps = Array.from({ length: 15 }, (_, i) => base + i * 60_000); // exactly every 60s
    const result = evaluateBeaconing(timestamps, { destination: '203.0.113.55', destinationPort: 443 });
    expect(result.matched).toBe(true);
    expect(result.score).toBeGreaterThan(0.9);
    expect(result.evidence.intervalMeanMs).toBe(60_000);
    expect(result.evidence.sampleCount).toBe(15);
    expect(result.evidence.destination).toBe('203.0.113.55');
  });

  test('does not match irregular, jittery intervals', () => {
    const base = Date.UTC(2026, 7, 19, 10, 0, 0);
    const jitters = [5, 120, 8, 200, 3, 90, 300, 15, 240, 60, 180, 30, 210, 45];
    let t = base;
    const timestamps = [t];
    for (const j of jitters) {
      t += j * 1000;
      timestamps.push(t);
    }
    const result = evaluateBeaconing(timestamps, { destination: '203.0.113.55' });
    expect(result.matched).toBe(false);
  });

  test('does not match below the minimum sample count, even with perfect regularity', () => {
    const base = Date.UTC(2026, 7, 19, 10, 0, 0);
    const timestamps = [base, base + 60_000, base + 120_000]; // only 3 samples, minSamples default is 6
    const result = evaluateBeaconing(timestamps, { destination: '203.0.113.55' });
    expect(result.matched).toBe(false);
    expect(result.evidence.sampleCount).toBe(3);
  });

  test('does not match when the mean interval exceeds the configured window', () => {
    const base = Date.UTC(2026, 7, 19, 10, 0, 0);
    const timestamps = Array.from({ length: 8 }, (_, i) => base + i * 60 * 60_000); // every hour
    const result = evaluateBeaconing(timestamps, { destination: '203.0.113.55' }, { maxMeanIntervalMs: 30 * 60_000 });
    expect(result.matched).toBe(false);
  });
});
