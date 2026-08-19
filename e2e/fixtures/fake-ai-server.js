// @ts-check
// A minimal stand-in for a real AI provider's HTTP endpoint, used only by
// ai-detections.spec.js. It always returns one canned "candidate detection"
// referencing fields that actually exist in the ssh_auth sample dataset -
// the point of this fixture is to exercise the real network call from the
// backend (AI_PROVIDER=custom pointed at this server), the real prompt
// send/parse path, and the real deterministic re-verification, not to
// simulate a specific AI model's behavior.
'use strict';

const http = require('http');

const PORT = Number(process.env.FAKE_AI_PORT || 4200);

const candidate = {
  name: 'AI-observed repeated auth failures (stub)',
  category: 'authentication',
  severity: 'high',
  confidence: 0.8,
  description: 'The AI stub observed repeated authentication failures in the real normalized sample.',
  mitreHint: 'brute_force',
  evidence: ['Stub AI provider - deterministic canned response for E2E testing.'],
  ruleConditions: [{ field: 'event.outcome', value: 'failure', exact: true }],
};

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify([candidate]) } }] }));
  });
});

server.listen(PORT, '127.0.0.1', () => {
  // eslint-disable-next-line no-console
  console.log(`Fake AI server listening on port ${PORT}`);
});
