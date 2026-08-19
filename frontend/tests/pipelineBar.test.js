import { test, describe, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { setStages, renderPipelineBar } from '../js/pipelineBar.js';
import { state } from '../js/state.js';

const STAGES = [
  { id: 'ingest', order: 1, label: 'Ingest', description: 'Load logs' },
  { id: 'discover', order: 2, label: 'Discover', description: 'Discover fields' },
  { id: 'ecs-map', order: 3, label: 'ECS Map', description: 'Map to ECS' },
];

function resetState() {
  Object.assign(state, {
    fieldDiscovery: null,
    mappings: null,
    normalizeResult: null,
    detections: null,
    rules: [],
    lastTestResult: null,
    lastTuning: null,
  });
}

describe('renderPipelineBar', () => {
  before(() => {
    const dom = new JSDOM('<!doctype html><body><div id="pipelineBar"></div></body>');
    globalThis.document = dom.window.document;
  });

  beforeEach(() => {
    resetState();
    setStages(STAGES);
  });

  test('marks the resolved current stage and leaves later stages with no class', () => {
    // No pipeline progress yet -> resolveStage() returns 'ingest' (order 1).
    renderPipelineBar();
    const container = document.getElementById('pipelineBar');
    const steps = [...container.querySelectorAll('.pipeline-step')];
    assert.equal(steps.length, 3);
    assert.ok(steps[0].className.includes('current'));
    assert.ok(!steps[1].className.includes('current') && !steps[1].className.includes('done'));
    assert.ok(!steps[2].className.includes('current') && !steps[2].className.includes('done'));
  });

  test('marks earlier stages as done and the resolved stage as current', () => {
    state.fieldDiscovery = { fields: [] }; // resolveStage() -> 'discover' (order 2)
    renderPipelineBar();
    const container = document.getElementById('pipelineBar');
    const steps = [...container.querySelectorAll('.pipeline-step')];
    assert.ok(steps[0].className.includes('done'));
    assert.ok(steps[1].className.includes('current'));
    assert.ok(!steps[2].className.includes('done') && !steps[2].className.includes('current'));
  });

  test('escapes the stage label and description', () => {
    setStages([{ id: 'x', order: 1, label: '<b>x</b>', description: '"quoted"' }]);
    renderPipelineBar();
    const html = document.getElementById('pipelineBar').innerHTML;
    assert.ok(!html.includes('<b>x</b>'));
    assert.ok(html.includes('&lt;b&gt;x&lt;/b&gt;'));
    assert.ok(html.includes('&quot;quoted&quot;'));
  });

  test('does nothing when no stages have been set', () => {
    setStages([]);
    const container = document.getElementById('pipelineBar');
    container.innerHTML = 'unchanged';
    renderPipelineBar();
    assert.equal(container.innerHTML, 'unchanged');
  });
});
