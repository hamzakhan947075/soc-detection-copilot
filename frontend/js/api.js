const BASE = '/api';

async function handle(res) {
  let body;
  try {
    body = await res.json();
  } catch (_err) {
    body = null;
  }
  if (!res.ok) {
    const message = (body && body.error) || `Request failed with status ${res.status}`;
    const err = new Error(message);
    // Structured AI-provider errors (see backend ai/aiErrors.js) carry a
    // stable `code`/`retryable` alongside the message - attach whatever
    // extra fields the response body has so any caller can branch on them,
    // not just display the message.
    if (body && typeof body === 'object') {
      for (const [key, value] of Object.entries(body)) {
        if (key !== 'error') err[key] = value;
      }
    }
    throw err;
  }
  return body;
}

export const api = {
  getAuthStatus: () => fetch(`${BASE}/auth/status`).then(handle),
  login: (password) =>
    fetch(`${BASE}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) }).then(handle),
  logout: () => fetch(`${BASE}/auth/logout`, { method: 'POST' }).then(handle),

  getPipeline: () => fetch(`${BASE}/pipeline`).then(handle),
  getMitre: () => fetch(`${BASE}/mitre/techniques`).then(handle),
  getAiStatus: () => fetch(`${BASE}/ai/status`).then(handle),
  getAiProviders: () => fetch(`${BASE}/ai/providers`).then(handle),
  setAiConfig: (payload) =>
    fetch(`${BASE}/ai/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).then(handle),
  clearAiConfig: () => fetch(`${BASE}/ai/config`, { method: 'DELETE' }).then(handle),
  testAiConfig: () => fetch(`${BASE}/ai/test`, { method: 'POST' }).then(handle),
  getSamples: () => fetch(`${BASE}/samples`).then(handle),
  loadSample: (name) => fetch(`${BASE}/samples/${encodeURIComponent(name)}/load`, { method: 'POST' }).then(handle),

  uploadFile: (file) => {
    const form = new FormData();
    form.append('file', file);
    return fetch(`${BASE}/sessions`, { method: 'POST', body: form }).then(handle);
  },
  pasteText: (text, filename) =>
    fetch(`${BASE}/sessions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, filename }),
    }).then(handle),

  getSession: (id) => fetch(`${BASE}/sessions/${id}`).then(handle),
  getFields: (id) => fetch(`${BASE}/sessions/${id}/fields`).then(handle),
  getSuggestedMappings: (id) => fetch(`${BASE}/sessions/${id}/mappings/suggested`).then(handle),
  putMappings: (id, mappings) =>
    fetch(`${BASE}/sessions/${id}/mappings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mappings }),
    }).then(handle),
  explainMapping: (id, mapping) =>
    fetch(`${BASE}/sessions/${id}/mappings/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(mapping),
    }).then(handle),
  normalize: (id) => fetch(`${BASE}/sessions/${id}/normalize`, { method: 'POST' }).then(handle),
  getNormalizedSample: (id) => fetch(`${BASE}/sessions/${id}/normalized/sample`).then(handle),

  detect: (id) => fetch(`${BASE}/sessions/${id}/detect`, { method: 'POST' }).then(handle),
  getDetections: (id) => fetch(`${BASE}/sessions/${id}/detections`).then(handle),
  explainDetection: (id, detectionId) => fetch(`${BASE}/sessions/${id}/detections/${detectionId}/explain`).then(handle),
  explainFalsePositives: (id, ruleId) => fetch(`${BASE}/sessions/${id}/rules/${ruleId}/explain-fp`).then(handle),

  createRule: (id, payload) =>
    fetch(`${BASE}/sessions/${id}/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).then(handle),
  getRules: (id) => fetch(`${BASE}/sessions/${id}/rules`).then(handle),
  testRule: (id, ruleId) => fetch(`${BASE}/sessions/${id}/rules/${ruleId}/test`, { method: 'POST' }).then(handle),
  tuneRule: (id, ruleId) => fetch(`${BASE}/sessions/${id}/rules/${ruleId}/tune`).then(handle),
  getReport: (id, ruleId, format) => fetch(`${BASE}/sessions/${id}/rules/${ruleId}/report?format=${format}`).then((res) => (format === 'json' ? handle(res) : res.text())),

  getDashboard: (id) => fetch(`${BASE}/sessions/${id}/dashboard`).then(handle),

  esStatus: () => fetch(`${BASE}/elasticsearch/status`).then(handle),
  esTestConnection: () => fetch(`${BASE}/elasticsearch/test-connection`, { method: 'POST' }).then(handle),
  esIndices: () => fetch(`${BASE}/elasticsearch/indices`).then(handle),
  esFetch: (payload) =>
    fetch(`${BASE}/elasticsearch/fetch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).then(handle),
};
