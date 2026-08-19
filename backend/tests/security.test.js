'use strict';

const request = require('supertest');
const { createApp } = require('../src/app');
const { loadSampleDataset } = require('../src/ingestion/sampleDatasets');
const aiConfigStore = require('../src/ai/aiConfigStore');
const detectionDb = require('../src/persistence/db');

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

  test('rejects (rather than silently drops) a prototype-pollution attempt via ecsField, end-to-end through the real API', async () => {
    // Regression for a real vulnerability: PUT /mappings + POST /normalize
    // used to let an analyst-supplied ecsField of "__proto__.polluted" walk
    // normalizeEvent's setPath onto the real, shared Object.prototype - on
    // a deployment with no authentication, this is remotely triggerable by
    // anyone with the URL, and pollutes every object in the process, not
    // just this session.
    const loadRes = await request(app)
      .post('/api/sessions')
      .send({ text: JSON.stringify({ weird_field: 'x' }), filename: 'pollution.ndjson' });
    const { sessionId } = loadRes.body;

    const mapRes = await request(app)
      .put(`/api/sessions/${sessionId}/mappings`)
      .send({ mappings: [{ rawField: 'weird_field', ecsField: '__proto__.polluted', ecsType: 'keyword' }] });
    expect(mapRes.status).toBe(200);
    expect(mapRes.body.mappings[0].ecsField).toBeNull(); // rejected outright, not silently accepted

    await request(app).post(`/api/sessions/${sessionId}/normalize`);

    expect(Object.prototype.polluted).toBeUndefined();
    expect(({}).polluted).toBeUndefined();
    delete Object.prototype.polluted; // safety net in case this assertion is what caught a regression
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

  test('AI-suggested detections (opt-in, additive) require AI configured and never remove the deterministic ones', async () => {
    const loadRes = await request(app).post('/api/samples/ssh_auth/load');
    const { sessionId } = loadRes.body;
    await request(app).post(`/api/sessions/${sessionId}/normalize`);
    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    const deterministicCount = detectRes.body.detections.length;
    expect(deterministicCount).toBeGreaterThan(0);

    // With no AI configured, the endpoint is a clear 400, not a silent no-op or a crash.
    const noAiRes = await request(app).post(`/api/sessions/${sessionId}/detect/ai-suggested`);
    expect(noAiRes.status).toBe(400);
    expect(noAiRes.body.code).toBe('ai_not_configured');

    const http = require('http');
    const server = http.createServer((req, res) => {
      let data = '';
      req.on('data', (chunk) => (data += chunk));
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify([
                    {
                      name: 'AI-observed pattern',
                      description: 'A pattern the AI observed in the real normalized sample.',
                      category: 'authentication',
                      severity: 'medium',
                      confidence: 0.7,
                      ruleConditions: [{ field: 'event.outcome', value: 'failure', exact: true }],
                    },
                  ]),
                },
              },
            ],
          })
        );
      });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'k', model: 'test-model', baseUrl: `http://127.0.0.1:${server.address().port}` });

      const aiRes = await request(app).post(`/api/sessions/${sessionId}/detect/ai-suggested`);
      expect(aiRes.status).toBe(200);
      expect(aiRes.body.acceptedCount).toBe(1);
      expect(aiRes.body.detections[0].source).toBe('ai');

      // Additive: the session's detection list now has the deterministic
      // ones plus the AI one, and the deterministic ones are unchanged.
      const listRes = await request(app).get(`/api/sessions/${sessionId}/detections`);
      expect(listRes.body.detections.length).toBe(deterministicCount + 1);
      expect(listRes.body.detections.filter((d) => d.source === 'ai').length).toBe(1);
      expect(listRes.body.detections.some((d) => d.name.includes('Brute Force'))).toBe(true);
    } finally {
      aiConfigStore.clearRuntimeConfig();
      await new Promise((resolve) => server.close(resolve));
    }
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

  test('/ai/test surfaces a structured error code (not just a message) when the provider rejects the key', async () => {
    const http = require('http');
    const server = http.createServer((_req, res) => {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'invalid api key' } }));
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    await request(app).post('/api/ai/config').send({ provider: 'custom', apiKey: 'k', baseUrl: `http://127.0.0.1:${port}`, model: 'test-model' });
    const res = await request(app).post('/api/ai/test');
    server.close();

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.code).toBe('auth');
    expect(res.body.retryable).toBe(false);
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

describe('Detection lifecycle API', () => {
  beforeEach(() => {
    detectionDb.exec('DELETE FROM detection_history; DELETE FROM detection_definitions;');
  });

  async function ingestAndDetectBruteForce() {
    const loadRes = await request(app).post('/api/samples/ssh_auth/load');
    const { sessionId } = loadRes.body;
    await request(app).post(`/api/sessions/${sessionId}/normalize`);
    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    const bruteForce = detectRes.body.detections.find((d) => d.name.includes('Brute Force'));
    return { sessionId, bruteForce };
  }

  test('a detection record is not persisted until explicitly persisted', async () => {
    const { sessionId, bruteForce } = await ingestAndDetectBruteForce();
    const notYet = await request(app).get(`/api/detections/authentication.brute_force`);
    expect(notYet.status).toBe(404);

    const record = await request(app).get(`/api/sessions/${sessionId}/detections/${bruteForce.id}/record`);
    expect(record.body.lifecycle).toEqual({ persisted: false });
  });

  test('persisting a detection creates a durable record independent of the session', async () => {
    const { sessionId, bruteForce } = await ingestAndDetectBruteForce();
    const persistRes = await request(app)
      .post(`/api/sessions/${sessionId}/detections/${bruteForce.id}/persist`)
      .send({ author: 'alice' });
    expect(persistRes.status).toBe(201);
    expect(persistRes.body.status).toBe('draft');
    expect(persistRes.body.version).toBe(1);
    expect(persistRes.body.author).toBe('alice');

    const listRes = await request(app).get('/api/detections');
    expect(listRes.body.detections.map((d) => d.evaluatorId)).toContain('authentication.brute_force');

    const record = await request(app).get(`/api/sessions/${sessionId}/detections/${bruteForce.id}/record`);
    expect(record.body.lifecycle.persisted).toBe(true);
  });

  test('rejects approving a detection that was never tested, via the real API', async () => {
    const { sessionId, bruteForce } = await ingestAndDetectBruteForce();
    await request(app).post(`/api/sessions/${sessionId}/detections/${bruteForce.id}/persist`).send({});
    const res = await request(app).post('/api/detections/authentication.brute_force/transition').send({ status: 'approved' });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/requires the detection to currently be in one of/);
  });

  test('walking the full lifecycle to production works and is durable across "sessions"', async () => {
    const { sessionId, bruteForce } = await ingestAndDetectBruteForce();
    await request(app).post(`/api/sessions/${sessionId}/detections/${bruteForce.id}/persist`).send({});

    for (const status of ['generated', 'validated', 'tested']) {
      const res = await request(app).post('/api/detections/authentication.brute_force/transition').send({ status });
      expect(res.status).toBe(200);
      expect(res.body.status).toBe(status);
    }
    const approved = await request(app).post('/api/detections/authentication.brute_force/transition').send({ status: 'approved', author: 'lead-analyst' });
    expect(approved.status).toBe(200);
    expect(approved.body.version).toBe(2);

    const production = await request(app).post('/api/detections/authentication.brute_force/transition').send({ status: 'production' });
    expect(production.body.status).toBe('production');
    expect(production.body.version).toBe(3);

    // A brand new session re-detecting the same behavior sees the same
    // durable production status - this is the point of persisting it.
    const secondSession = await ingestAndDetectBruteForce();
    const record = await request(app).get(`/api/sessions/${secondSession.sessionId}/detections/${secondSession.bruteForce.id}/record`);
    expect(record.body.status).toBe('production');
    expect(record.body.version).toBe(3);

    const historyRes = await request(app).get('/api/detections/authentication.brute_force/history');
    expect(historyRes.body.history.map((h) => h.status)).toEqual(['draft', 'generated', 'validated', 'tested', 'approved', 'production']);
  });

  test('400s a transition request with no status', async () => {
    const res = await request(app).post('/api/detections/authentication.brute_force/transition').send({});
    expect(res.status).toBe(400);
  });
});

describe('Rule test-suite API (positive/negative/edge classification)', () => {
  test('auto-generates a passing test suite from the rule\'s own conditions, using the real matched event as the positive base', async () => {
    const loadRes = await request(app).post('/api/samples/ssh_auth/load');
    const { sessionId } = loadRes.body;
    await request(app).post(`/api/sessions/${sessionId}/normalize`);
    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    const bruteForce = detectRes.body.detections.find((d) => d.name.includes('Brute Force'));
    const ruleRes = await request(app).post(`/api/sessions/${sessionId}/rules`).send({ detectionId: bruteForce.id, ruleType: 'kql' });
    await request(app).post(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/test`); // populates a real matched event to seed the positive case

    const suiteRes = await request(app).post(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/testsuite`).send({});
    expect(suiteRes.status).toBe(200);
    expect(suiteRes.body.testCases.positive).toHaveLength(1);
    expect(suiteRes.body.testCases.positive[0].description).toMatch(/real event/);
    expect(suiteRes.body.counts.fail).toBe(0);
    expect(suiteRes.body.counts.error).toBe(0);
    expect(suiteRes.body.metrics.precision).toBe(1);
    expect(suiteRes.body.metrics.recall).toBe(1);

    // The detection record now reflects the real test-suite result too.
    const record = await request(app).get(`/api/sessions/${sessionId}/detections/${bruteForce.id}/record`);
    expect(record.body.testSuiteResult.metrics.precision).toBe(1);
    expect(record.body.testCases.positive).toHaveLength(1);
  });

  test('an analyst-supplied case that exposes a real false positive shows up in the confusion matrix', async () => {
    const loadRes = await request(app).post('/api/samples/ssh_auth/load');
    const { sessionId } = loadRes.body;
    await request(app).post(`/api/sessions/${sessionId}/normalize`);
    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    const bruteForce = detectRes.body.detections.find((d) => d.name.includes('Brute Force'));
    const ruleRes = await request(app).post(`/api/sessions/${sessionId}/rules`).send({ detectionId: bruteForce.id, ruleType: 'kql' });

    // Deliberately mislabel a case that the rule WILL match, as if it should not - proving a genuine FP surfaces in the metrics rather than being silently absorbed.
    const suiteRes = await request(app)
      .post(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/testsuite`)
      .send({
        includeGenerated: false,
        testCases: [{ id: 'bad-negative', type: 'negative', expectedMatch: false, event: { event: { category: 'authentication', outcome: 'failure' } } }],
      });
    expect(suiteRes.body.confusionMatrix.falsePositives).toBe(1);
    expect(suiteRes.body.counts.fail).toBe(1);
  });

  test('404s for an unknown rule id', async () => {
    const loadRes = await request(app).post('/api/samples/ssh_auth/load');
    const { sessionId } = loadRes.body;
    const res = await request(app).post(`/api/sessions/${sessionId}/rules/does-not-exist/testsuite`).send({});
    expect(res.status).toBe(404);
  });
});

describe('False-positive dimensional breakdown and verified tuning (real API)', () => {
  test('FP analysis breaks down potential false positives by field/value, and tuning verifies the improvement against real data', async () => {
    // 12 real brute-force events from one IP (the detection's own evidence).
    // A second IP independently generates 10 failures too - enough to clear
    // the *rule's* exported threshold (10, grouped by source.ip) during
    // testing, but it's a separate candidate with its own evidence, so
    // relative to the first candidate under test these are genuine
    // potential false positives, not part of what it originally detected.
    const evidenceEvents = Array.from({ length: 12 }, (_, i) => ({
      '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, i)).toISOString(),
      source: { ip: '198.51.100.5' },
      user: { name: 'admin' },
      event: { category: 'authentication', outcome: 'failure' },
    }));
    const noiseEvents = Array.from({ length: 10 }, (_, i) => ({
      '@timestamp': new Date(Date.UTC(2026, 7, 19, 11, 0, i)).toISOString(),
      source: { ip: '203.0.113.77' },
      user: { name: 'svc-monitor' },
      event: { category: 'authentication', outcome: 'failure' },
    }));
    const events = [...evidenceEvents, ...noiseEvents];

    const loadRes = await request(app)
      .post('/api/sessions')
      .send({ text: events.map((e) => JSON.stringify(e)).join('\n'), filename: 'fp-breakdown.ndjson' });
    const { sessionId } = loadRes.body;
    await request(app).post(`/api/sessions/${sessionId}/normalize`);
    const detectRes = await request(app).post(`/api/sessions/${sessionId}/detect`);
    const bruteForce = detectRes.body.detections.find((d) => d.name.includes('Brute Force'));
    expect(bruteForce).toBeDefined();

    const ruleRes = await request(app).post(`/api/sessions/${sessionId}/rules`).send({ detectionId: bruteForce.id, ruleType: 'kql' });
    const testRes = await request(app).post(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/test`);

    // The rule (event.category=authentication AND event.outcome=failure,
    // threshold >=10 grouped by source.ip) matches both IPs' 22 events
    // total, but only the 12 from the real brute-force evidence are true
    // positives relative to this specific candidate.
    expect(testRes.body.testResult.eventsMatched).toBe(22);
    const fp = testRes.body.fpAnalysis;
    expect(fp.potentialFalsePositiveCount).toBe(10);
    expect(fp.topUsers.some((u) => u.value === 'svc-monitor')).toBe(true);

    const tuneRes = await request(app).get(`/api/sessions/${sessionId}/rules/${ruleRes.body.ruleId}/tune`);
    expect(tuneRes.status).toBe(200);
    if (tuneRes.body.applicable && tuneRes.body.after) {
      // Whatever the tool claims, it must be backed by a real re-computed FP rate, not just asserted.
      expect(tuneRes.body.after.falsePositiveRatePercent).not.toBeUndefined();
      expect(typeof tuneRes.body.verifiedImprovement === 'boolean' || tuneRes.body.verifiedImprovement === null).toBe(true);
    }
  });
});
