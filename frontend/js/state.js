export const state = {
  sessionId: null,
  logSource: null,
  fieldDiscovery: null,
  mappings: null, // [{rawField, ecsField, ecsType, confidence, status}]
  normalizeResult: null,
  detections: null,
  selectedDetectionId: null,
  rules: [], // [{ruleId, ...ruleObject}]
  selectedRuleId: null,
  lastTestResult: null,
  lastFpAnalysis: null,
  lastTuning: null,
  stage: 'ingest',
  aiEnabled: false,
};

const listeners = new Set();

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function notify() {
  listeners.forEach((fn) => fn(state));
}

export function setStatus(message, isError) {
  const el = document.getElementById('statusMessage');
  if (!el) return;
  el.textContent = message || '';
  el.style.color = isError ? '#ff5c73' : '';
}

export function setSessionLabel(text) {
  const el = document.getElementById('sessionLabel');
  if (el) el.textContent = text;
}

export function resolveStage() {
  if (state.lastTuning) return 'tune';
  if (state.lastTestResult) return 'validate';
  if (state.rules.length > 0) return 'generate-rule';
  if (state.detections) return 'detect';
  if (state.normalizeResult) return 'ecs-map';
  if (state.mappings) return 'normalize';
  if (state.fieldDiscovery) return 'discover';
  return 'ingest';
}
