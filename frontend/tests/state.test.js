import { test, describe, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { state, setStatus, setSessionLabel, resolveStage } from '../js/state.js';

function resetState() {
  Object.assign(state, {
    sessionId: null,
    logSource: null,
    fieldDiscovery: null,
    mappings: null,
    normalizeResult: null,
    detections: null,
    selectedDetectionId: null,
    rules: [],
    selectedRuleId: null,
    lastTestResult: null,
    lastFpAnalysis: null,
    lastTuning: null,
    stage: 'ingest',
    aiEnabled: false,
  });
}

describe('resolveStage', () => {
  beforeEach(resetState);

  test('defaults to "ingest" when nothing has happened yet', () => {
    assert.equal(resolveStage(), 'ingest');
  });

  test('advances through the pipeline in priority order, latest stage wins', () => {
    state.fieldDiscovery = { fields: [] };
    assert.equal(resolveStage(), 'discover');

    state.mappings = [];
    assert.equal(resolveStage(), 'normalize');

    state.normalizeResult = {};
    assert.equal(resolveStage(), 'ecs-map');

    state.detections = [];
    assert.equal(resolveStage(), 'detect');

    state.rules = [{ ruleId: 'r1' }];
    assert.equal(resolveStage(), 'generate-rule');

    state.lastTestResult = {};
    assert.equal(resolveStage(), 'validate');

    state.lastTuning = {};
    assert.equal(resolveStage(), 'tune');
  });

  test('an empty rules array does not count as having generated a rule', () => {
    state.detections = [];
    state.rules = [];
    assert.equal(resolveStage(), 'detect');
  });
});

describe('setStatus / setSessionLabel (DOM)', () => {
  before(() => {
    const dom = new JSDOM('<!doctype html><body><div id="statusMessage"></div><div id="sessionLabel"></div></body>');
    globalThis.document = dom.window.document;
  });

  test('setStatus writes the message as text and leaves default color for a non-error message', () => {
    setStatus('All good', false);
    const el = document.getElementById('statusMessage');
    assert.equal(el.textContent, 'All good');
    assert.equal(el.style.color, '');
  });

  test('setStatus applies the error color for an error message', () => {
    setStatus('Something broke', true);
    const el = document.getElementById('statusMessage');
    assert.equal(el.textContent, 'Something broke');
    assert.equal(el.style.color, 'rgb(255, 92, 115)');
  });

  test('setStatus never writes markup - it uses textContent, not innerHTML', () => {
    setStatus('<img src=x onerror=alert(1)>', true);
    const el = document.getElementById('statusMessage');
    assert.equal(el.querySelector('img'), null);
    assert.equal(el.textContent, '<img src=x onerror=alert(1)>');
  });

  test('setStatus is a no-op when the target element does not exist', () => {
    document.getElementById('statusMessage').remove();
    assert.doesNotThrow(() => setStatus('irrelevant', false));
  });

  test('setSessionLabel sets the session label text', () => {
    setSessionLabel('session-abc123');
    assert.equal(document.getElementById('sessionLabel').textContent, 'session-abc123');
  });
});
