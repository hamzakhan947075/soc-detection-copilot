'use strict';

const http = require('http');
const aiConfigStore = require('../src/ai/aiConfigStore');
const { suggestAiDetections, sanitizeCandidate, sanitizeCondition, buildDatasetSummary } = require('../src/detection-engine/aiDetectionSuggestor');

function startServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let data = '';
      req.on('data', (chunk) => (data += chunk));
      req.on('end', () => handler(res));
    });
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function chatResponse(content) {
  return { choices: [{ message: { content: JSON.stringify(content) } }] };
}

function jsonRes(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

const NORMALIZED_EVENTS = [
  { '@timestamp': '2026-01-01T00:00:00Z', 'user.name': 'admin', 'source.ip': '10.0.0.5', 'event.outcome': 'failure' },
  { '@timestamp': '2026-01-01T00:00:05Z', 'user.name': 'admin', 'source.ip': '10.0.0.5', 'event.outcome': 'failure' },
  { '@timestamp': '2026-01-01T00:00:10Z', 'user.name': 'admin', 'source.ip': '10.0.0.5', 'event.outcome': 'failure' },
  { '@timestamp': '2026-01-01T00:00:15Z', 'user.name': 'bob', 'source.ip': '10.0.0.9', 'event.outcome': 'success' },
];

describe('aiDetectionSuggestor - deterministic sanitizers', () => {
  const knownFields = new Set(['user.name', 'source.ip', 'event.outcome']);

  test('sanitizeCondition rejects a field that is not in the real dataset (a hallucinated field)', () => {
    expect(sanitizeCondition({ field: 'process.imaginary_field', value: 'x' }, knownFields)).toBeNull();
  });

  test('sanitizeCondition accepts exists/value/values shapes for a known field', () => {
    expect(sanitizeCondition({ field: 'user.name', exists: true }, knownFields)).toEqual({ field: 'user.name', exists: true });
    expect(sanitizeCondition({ field: 'user.name', value: 'admin', exact: true }, knownFields)).toEqual({ field: 'user.name', value: 'admin', exact: true });
    expect(sanitizeCondition({ field: 'user.name', values: ['admin', 'root'] }, knownFields)).toEqual({ field: 'user.name', values: ['admin', 'root'], exact: false });
  });

  test('sanitizeCondition rejects a condition with none of exists/value/values', () => {
    expect(sanitizeCondition({ field: 'user.name' }, knownFields)).toBeNull();
  });

  test('sanitizeCandidate drops a candidate with zero surviving conditions (all fields hallucinated)', () => {
    const result = sanitizeCandidate(
      { name: 'x', description: 'y', ruleConditions: [{ field: 'not.real', value: '1' }] },
      knownFields
    );
    expect(result).toBeNull();
  });

  test('sanitizeCandidate defaults an unrecognized category/severity rather than trusting the AI', () => {
    const result = sanitizeCandidate(
      { name: 'Odd pattern', description: 'desc', category: 'made-up-category', severity: 'apocalyptic', ruleConditions: [{ field: 'user.name', value: 'admin' }] },
      knownFields
    );
    expect(result.category).toBe('ai-suggested');
    expect(result.severity).toBe('medium');
  });

  test('sanitizeCandidate clamps an out-of-range confidence and rejects an unknown mitreHint', () => {
    const result = sanitizeCandidate(
      { name: 'x', description: 'y', confidence: 5, mitreHint: 'not_a_real_technique', ruleConditions: [{ field: 'user.name', value: 'admin' }] },
      knownFields
    );
    expect(result.confidence).toBe(1);
    expect(result.mitreHint).toBeNull();
  });

  test('sanitizeCandidate requires both a name and a description', () => {
    expect(sanitizeCandidate({ description: 'y', ruleConditions: [{ field: 'user.name', value: 'admin' }] }, knownFields)).toBeNull();
    expect(sanitizeCandidate({ name: 'x', ruleConditions: [{ field: 'user.name', value: 'admin' }] }, knownFields)).toBeNull();
  });
});

describe('buildDatasetSummary - keeps the prompt bounded regardless of dataset shape', () => {
  test('caps the serialized sample size even for events with many long field values (e.g. Sysmon-shaped data)', () => {
    // Regression: a real user hit a Groq 413 ("Request too large... TPM
    // Limit 8000, Requested 29632") because a field-rich dataset made the
    // sample size scale with field richness, not just event count. 40
    // events x 25 fields x 300-char values would previously have produced
    // a huge prompt; the byte-budget cap must still hold it well under
    // MAX_SAMPLE_CHARS regardless of how field-rich the source data is.
    const richEvents = Array.from({ length: 40 }, (_, i) => {
      const event = { '@timestamp': `2026-01-01T00:00:${String(i).padStart(2, '0')}Z` };
      for (let f = 0; f < 25; f++) {
        event[`process.field_${f}`] = 'x'.repeat(300);
      }
      return event;
    });

    const { sampleEvents } = buildDatasetSummary(richEvents);
    const serializedSize = JSON.stringify(sampleEvents).length;
    expect(serializedSize).toBeLessThan(15000); // MAX_SAMPLE_CHARS (12000) plus one event's worth of slack
    expect(sampleEvents.length).toBeGreaterThan(0); // always keeps at least one event, even if it alone is large
  });

  test('truncates individual long string values', () => {
    const events = [{ 'process.command_line': 'a'.repeat(500) }];
    const { sampleEvents } = buildDatasetSummary(events);
    expect(sampleEvents[0]['process.command_line'].length).toBeLessThan(150);
  });

  test('caps the field list shown to the model separately from the full validation allowlist', () => {
    const events = [Object.fromEntries(Array.from({ length: 150 }, (_, i) => [`field_${i}`, 'v']))];
    const { fields, fieldsForPrompt } = buildDatasetSummary(events);
    expect(fields.length).toBe(150); // full set, used for validation
    expect(fieldsForPrompt.length).toBeLessThanOrEqual(80); // capped subset actually sent to the model
  });
});

describe('suggestAiDetections - end to end against a real local server', () => {
  let server;

  afterEach(async () => {
    aiConfigStore.clearRuntimeConfig();
    if (server) await new Promise((resolve) => server.close(resolve));
    server = null;
  });

  test('throws a clear error when AI is not configured (no meaningful fallback exists for this feature)', async () => {
    await expect(suggestAiDetections(NORMALIZED_EVENTS)).rejects.toThrow(/AI is not configured/);
  });

  test('accepts a real, field-grounded candidate and rejects a hallucinated-field candidate and a zero-match candidate', async () => {
    server = await startServer((res) =>
      jsonRes(
        res,
        200,
        chatResponse([
          {
            name: 'Repeated admin auth failures from one source',
            category: 'authentication',
            severity: 'high',
            confidence: 0.9,
            description: 'The admin account failed to authenticate 3 times from the same source IP.',
            mitreHint: 'brute_force',
            evidence: ['3 failures from 10.0.0.5'],
            ruleConditions: [{ field: 'user.name', value: 'admin', exact: true }, { field: 'event.outcome', value: 'failure', exact: true }],
          },
          {
            name: 'Hallucinated field candidate',
            description: 'This references a field that does not exist in the dataset.',
            ruleConditions: [{ field: 'process.imaginary_field', value: 'whatever' }],
          },
          {
            name: 'Zero-match candidate',
            description: 'This condition is real but matches nothing in this sample.',
            ruleConditions: [{ field: 'user.name', value: 'nonexistent-user', exact: true }],
          },
        ])
      )
    );
    aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'k', model: 'test-model', baseUrl: `http://127.0.0.1:${server.address().port}` });

    const result = await suggestAiDetections(NORMALIZED_EVENTS);

    expect(result.rawSuggestedCount).toBe(3);
    expect(result.acceptedCount).toBe(1);
    expect(result.rejectedInvalidCount).toBe(1);
    expect(result.rejectedNoMatchCount).toBe(1);

    const [detection] = result.detections;
    expect(detection.source).toBe('ai');
    expect(detection.name).toBe('Repeated admin auth failures from one source');
    expect(detection.matchedEventIndexes).toEqual([0, 1, 2]);
    expect(detection.mitre.techniqueId).toBe('T1110.001');
    expect(detection.evidence[0]).toMatch(/Verified against real data: matched 3 of 4/);
  });

  test('assigns a distinct, stable mitreHint-shaped id for a candidate with no real MITRE mapping, instead of a generic collision-prone one', async () => {
    server = await startServer((res) =>
      jsonRes(
        res,
        200,
        chatResponse([
          {
            name: 'Unusual login time pattern',
            description: 'This admin account logged in at an unusual hour compared to its normal pattern.',
            ruleConditions: [{ field: 'user.name', value: 'admin', exact: true }],
          },
        ])
      )
    );
    aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'k', model: 'test-model', baseUrl: `http://127.0.0.1:${server.address().port}` });

    const result = await suggestAiDetections(NORMALIZED_EVENTS);
    expect(result.detections[0].mitreHint).toBe('ai_unusual_login_time_pattern');
    expect(result.detections[0].mitre.techniqueId).toBeNull();
    expect(result.detections[0].mitre.certain).toBe(false);
  });

  test('returns an empty, non-throwing result when the AI finds nothing worth flagging', async () => {
    server = await startServer((res) => jsonRes(res, 200, chatResponse([])));
    aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'k', model: 'test-model', baseUrl: `http://127.0.0.1:${server.address().port}` });

    const result = await suggestAiDetections(NORMALIZED_EVENTS);
    expect(result.detections).toEqual([]);
    expect(result.acceptedCount).toBe(0);
  });

  test('throws a clear error when the AI response is not valid JSON', async () => {
    server = await startServer((res) => jsonRes(res, 200, { choices: [{ message: { content: 'not json at all' } }] }));
    aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'k', model: 'test-model', baseUrl: `http://127.0.0.1:${server.address().port}` });

    await expect(suggestAiDetections(NORMALIZED_EVENTS)).rejects.toThrow(/not valid JSON/);
  });

  test('strips a markdown code fence the model added despite instructions not to', async () => {
    server = await startServer((res) =>
      jsonRes(res, 200, {
        choices: [
          {
            message: {
              content:
                '```json\n' +
                JSON.stringify([
                  {
                    name: 'Fenced response candidate',
                    description: 'The model wrapped this in a code fence anyway.',
                    ruleConditions: [{ field: 'user.name', value: 'admin', exact: true }],
                  },
                ]) +
                '\n```',
            },
          },
        ],
      })
    );
    aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'k', model: 'test-model', baseUrl: `http://127.0.0.1:${server.address().port}` });

    const result = await suggestAiDetections(NORMALIZED_EVENTS);
    expect(result.acceptedCount).toBe(1);
    expect(result.detections[0].name).toBe('Fenced response candidate');
  });
});
