'use strict';

const request = require('supertest');
const { createApp } = require('../src/app');
const { loadSampleDataset } = require('../src/ingestion/sampleDatasets');
const aiConfigStore = require('../src/ai/aiConfigStore');

const app = createApp();

describe('API security', () => {
  test('rejects a request with neither file nor text', async () => {
    const res = await request(app).post('/api/sessions').send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  test('rejects file uploads with a disallowed extension', async () => {
    const res = await request(app)
      .post('/api/sessions')
      .attach('file', Buffer.from('#!/bin/sh\necho hi'), { filename: 'malicious.sh', contentType: 'text/plain' });
    expect(res.status).toBe(400);
  });

  test('accepts a valid ndjson upload', async () => {
    const res = await request(app)
      .post('/api/sessions')
      .attach('file', Buffer.from('{"message":"test"}\n'), { filename: 'sample.ndjson', contentType: 'application/x-ndjson' });
    expect(res.status).toBe(201);
    expect(res.body.sessionId).toBeDefined();
  });

  test('never reflects internal error details for a broken request', async () => {
    const res = await request(app).get('/api/sessions/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body.error).not.toMatch(/node_modules|at Object|\.js:\d+/);
  });

  test('rejects an unmapped route with a generic 404', async () => {
    const res = await request(app).get('/api/totally-made-up-route');
    expect(res.status).toBe(404);
  });

  test('sets standard security headers via helmet', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });
});

describe('Sample dataset path traversal protection', () => {
  test('does not allow escaping the sample-data directory', () => {
    expect(loadSampleDataset('../../etc/passwd')).toBeNull();
    expect(loadSampleDataset('..%2f..%2fetc%2fpasswd')).toBeNull();
  });

  test('loads a legitimate sample dataset by name', () => {
    const dataset = loadSampleDataset('ssh_auth');
    expect(dataset).not.toBeNull();
    expect(dataset.rawText.length).toBeGreaterThan(0);
  });
});

describe('End-to-end pipeline smoke test via API', () => {
  test('runs the full workflow against the SSH sample dataset', async () => {
    const loadRes = await request(app).post('/api/samples/ssh_auth/load');
    expect(loadRes.status).toBe(201);
    const { sessionId, logSource } = loadRes.body;
    expect(logSource.source).toBe('Linux SSH');

    const normalizeRes = await request(app).post(`/api/sessions/${sessionId}/normalize`);
    expect(normalizeRes.status).toBe(200);
    expect(normalizeRes.body.coveragePercent).toBeGreaterThan(0);

    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    expect(detectRes.status).toBe(200);
    const bruteForce = detectRes.body.detections.find((d) => d.name.includes('Brute Force'));
    expect(bruteForce).toBeDefined();

    const ruleRes = await request(app)
      .post(`/api/sessions/${sessionId}/rules`)
      .send({ detectionId: bruteForce.id, ruleType: 'kql' });
    expect(ruleRes.status).toBe(201);
    expect(ruleRes.body.queryValid).toBe(true);

    const testRes = await request(app).post(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/test`);
    expect(testRes.status).toBe(200);
    expect(testRes.body.testResult.eventsMatched).toBeGreaterThan(0);

    const reportRes = await request(app).get(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/report?format=markdown`);
    expect(reportRes.status).toBe(200);
    expect(reportRes.text).toContain('Detection Engineering Report');
  });

  test('a rule generated for a pattern-based detection (reverse shell) actually matches the events that triggered it', async () => {
    // Regression test: rule generation used to fall back to a generic
    // event.category filter unrelated to how the detection actually fired,
    // so testing the rule against the same dataset it came from produced
    // zero matches. Each behavior module now supplies its own accurate
    // ruleConditions, and this confirms the fix end-to-end via the API.
    const loadRes = await request(app).post('/api/samples/ssh_auth/load');
    const { sessionId } = loadRes.body;
    await request(app).post(`/api/sessions/${sessionId}/normalize`);
    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    const reverseShell = detectRes.body.detections.find((d) => d.name === 'Reverse Shell Indicator');
    expect(reverseShell).toBeDefined();

    const ruleRes = await request(app)
      .post(`/api/sessions/${sessionId}/rules`)
      .send({ detectionId: reverseShell.id, ruleType: 'kql' });
    expect(ruleRes.status).toBe(201);

    const testRes = await request(app).post(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/test`);
    expect(testRes.body.testResult.eventsMatched).toBeGreaterThan(0);
    expect(testRes.body.fpAnalysis.likelyTruePositiveCount).toBeGreaterThan(0);
  });

  test('a rule generated for an identity-based detection (root login) does not count a similarly-named user as a match', async () => {
    // Regression test: rule testing used to match conditions as a
    // case-insensitive substring, so a rule for user.name "root" would also
    // match a user named "rootkit" - inflating the reported match count with
    // a false positive baked into the test itself. ruleConditions for
    // identity fields now carry exact: true.
    const events = [
      { '@timestamp': '2026-08-19T10:00:00Z', user: { name: 'root' }, event: { outcome: 'success' }, source: { ip: '10.0.0.5' } },
      { '@timestamp': '2026-08-19T10:01:00Z', user: { name: 'rootkit' }, event: { outcome: 'success' }, source: { ip: '10.0.0.6' } },
    ];
    const loadRes = await request(app)
      .post('/api/sessions')
      .send({ text: events.map((e) => JSON.stringify(e)).join('\n'), filename: 'root-login.ndjson' });
    const { sessionId } = loadRes.body;
    await request(app).post(`/api/sessions/${sessionId}/normalize`);
    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    const rootLogin = detectRes.body.detections.find((d) => d.name === 'Direct Root Login');
    expect(rootLogin).toBeDefined();
    expect(rootLogin.matchedEventIndexes).toEqual([0]);

    const ruleRes = await request(app).post(`/api/sessions/${sessionId}/rules`).send({ detectionId: rootLogin.id, ruleType: 'kql' });
    const testRes = await request(app).post(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/test`);
    expect(testRes.body.testResult.eventsMatched).toBe(1);
  });

  test('the canonical detection record reflects rule generation and test status as they happen', async () => {
    const loadRes = await request(app).post('/api/samples/ssh_auth/load');
    const { sessionId } = loadRes.body;
    await request(app).post(`/api/sessions/${sessionId}/normalize`);
    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    const bruteForce = detectRes.body.detections.find((d) => d.name.includes('Brute Force'));

    const draftRecord = await request(app).get(`/api/sessions/${sessionId}/detections/${bruteForce.id}/record`);
    expect(draftRecord.status).toBe(200);
    expect(draftRecord.body.status).toBe('draft');
    expect(draftRecord.body.mitre.technique.id).toBe('T1110');
    expect(draftRecord.body.logSource.source).toBe('Linux SSH');

    const ruleRes = await request(app).post(`/api/sessions/${sessionId}/rules`).send({ detectionId: bruteForce.id, ruleType: 'kql' });
    await request(app).post(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/test`);

    const testedRecord = await request(app).get(`/api/sessions/${sessionId}/detections/${bruteForce.id}/record`);
    expect(testedRecord.body.status).toBe('tested');
    expect(testedRecord.body.query).toBeDefined();
    expect(testedRecord.body.testResult.eventsMatched).toBeGreaterThan(0);
  });

  test('404s for an unknown detection id', async () => {
    const loadRes = await request(app).post('/api/samples/ssh_auth/load');
    const { sessionId } = loadRes.body;
    const res = await request(app).get(`/api/sessions/${sessionId}/detections/does-not-exist/record`);
    expect(res.status).toBe(404);
  });

  test('a rule generated for the CIDR-based internal-to-external detection actually reproduces the match when tested', async () => {
    // Regression test for the CIDR evaluator work: this detection used to
    // render a rule that only checked both fields existed (a documented
    // gap), so testing it never proved anything. It now renders a real
    // cidr condition, and this proves end-to-end that testing the
    // generated rule against the same traffic that triggered it actually
    // matches - and that traffic between two internal hosts does not.
    const events = [
      ...Array.from({ length: 25 }, (_, i) => ({
        '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, i)).toISOString(),
        source: { ip: '10.0.0.5' },
        destination: { ip: '203.0.113.200' },
        event: { action: 'allowed' },
      })),
      { '@timestamp': '2026-08-19T10:01:00Z', source: { ip: '10.0.0.5' }, destination: { ip: '10.0.0.99' }, event: { action: 'allowed' } },
    ];
    const loadRes = await request(app)
      .post('/api/sessions')
      .send({ text: events.map((e) => JSON.stringify(e)).join('\n'), filename: 'internal-external.ndjson' });
    const { sessionId } = loadRes.body;
    await request(app).post(`/api/sessions/${sessionId}/normalize`);
    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    const anomaly = detectRes.body.detections.find((d) => d.name === 'Internal-to-External Traffic Anomaly');
    expect(anomaly).toBeDefined();

    const ruleRes = await request(app).post(`/api/sessions/${sessionId}/rules`).send({ detectionId: anomaly.id, ruleType: 'kql' });
    expect(ruleRes.body.query).toMatch(/source\.ip:.*10\.0\.0\.0\/8.*and not destination\.ip/);
    const testRes = await request(app).post(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/test`);
    expect(testRes.body.testResult.eventsMatched).toBe(25);
  });
});

describe('AI config API', () => {
  afterEach(() => {
    aiConfigStore.clearRuntimeConfig();
  });

  test('lists supported providers', async () => {
    const res = await request(app).get('/api/ai/providers');
    expect(res.status).toBe(200);
    const ids = res.body.providers.map((p) => p.id);
    expect(ids).toEqual(expect.arrayContaining(['anthropic', 'groq', 'openai', 'custom']));
  });

  test('rejects an unknown provider', async () => {
    const res = await request(app).post('/api/ai/config').send({ provider: 'not-real', apiKey: 'x' });
    expect(res.status).toBe(400);
  });

  test('rejects an empty API key', async () => {
    const res = await request(app).post('/api/ai/config').send({ provider: 'groq', apiKey: '' });
    expect(res.status).toBe(400);
  });

  test('accepts a valid Groq key and reports enabled status without leaking the raw key', async () => {
    const res = await request(app).post('/api/ai/config').send({ provider: 'groq', apiKey: 'gsk-test-key-value-12345' });
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(true);
    expect(JSON.stringify(res.body)).not.toContain('gsk-test-key-value-12345');

    const status = await request(app).get('/api/ai/status');
    expect(status.body.enabled).toBe(true);
    expect(JSON.stringify(status.body)).not.toContain('gsk-test-key-value-12345');
  });

  test('clearing the config disables AI again', async () => {
    await request(app).post('/api/ai/config').send({ provider: 'groq', apiKey: 'gsk-test-key' });
    const cleared = await request(app).delete('/api/ai/config');
    expect(cleared.body.source).not.toBe('session');
  });
});

describe('AI field-mapping check', () => {
  test('explains a mapped field with a deterministic fallback when AI is not configured', async () => {
    const ingestRes = await request(app).post('/api/samples/ssh_auth/load');
    const sessionId = ingestRes.body.sessionId;

    const res = await request(app)
      .post(`/api/sessions/${sessionId}/mappings/explain`)
      .send({ rawField: 'username', ecsField: 'user.name', ecsType: 'keyword', confidence: 0.9 });
    expect(res.status).toBe(200);
    expect(res.body.source).toBe('deterministic');
    expect(res.body.text).toMatch(/username/);
  });

  test('explains an unmapped field without a raw ECS field name', async () => {
    const ingestRes = await request(app).post('/api/samples/ssh_auth/load');
    const sessionId = ingestRes.body.sessionId;

    const res = await request(app)
      .post(`/api/sessions/${sessionId}/mappings/explain`)
      .send({ rawField: 'totally_custom_field', ecsField: null });
    expect(res.status).toBe(200);
    expect(res.body.text).toMatch(/custom/i);
  });

  test('rejects a request missing rawField', async () => {
    const ingestRes = await request(app).post('/api/samples/ssh_auth/load');
    const sessionId = ingestRes.body.sessionId;

    const res = await request(app).post(`/api/sessions/${sessionId}/mappings/explain`).send({});
    expect(res.status).toBe(400);
  });

  test('404s for an unknown session', async () => {
    const res = await request(app)
      .post('/api/sessions/does-not-exist/mappings/explain')
      .send({ rawField: 'username' });
    expect(res.status).toBe(404);
  });
});
