import { api } from './api.js';
import { state, setStatus } from './state.js';
import { controller } from './controller.js';
import { setStages, renderPipelineBar } from './pipelineBar.js';

import * as overview from './tabs/overview.js';
import * as ingestion from './tabs/ingestion.js';
import * as fields from './tabs/fields.js';
import * as ecsMapping from './tabs/ecsMapping.js';
import * as detection from './tabs/detection.js';
import * as mitre from './tabs/mitre.js';
import * as ruleBuilder from './tabs/ruleBuilder.js';
import * as ruleTesting from './tabs/ruleTesting.js';
import * as falsePositive from './tabs/falsePositive.js';
import * as tuning from './tabs/tuning.js';
import * as investigation from './tabs/investigation.js';
import * as reports from './tabs/reports.js';
import * as settings from './tabs/settings.js';

const TABS = [
  overview,
  ingestion,
  fields,
  ecsMapping,
  detection,
  mitre,
  ruleBuilder,
  ruleTesting,
  falsePositive,
  tuning,
  investigation,
  reports,
  settings,
];

let activeTabId = overview.id;

async function renderActiveTab() {
  const tab = TABS.find((t) => t.id === activeTabId) || TABS[0];
  const content = document.getElementById('content');
  try {
    await tab.render(content);
  } catch (err) {
    content.innerHTML = `<div class="card"><div class="error-box">Failed to render this view: ${escapeForDisplay(err.message)}</div></div>`;
  }
  renderPipelineBar();
  renderTabsBar();
}

function escapeForDisplay(msg) {
  const div = document.createElement('div');
  div.textContent = msg;
  return div.innerHTML;
}

function renderTabsBar() {
  const tabsEl = document.getElementById('tabs');
  tabsEl.innerHTML = TABS.map((t) => `<button class="tab-btn ${t.id === activeTabId ? 'active' : ''}" data-tab="${t.id}">${t.label}</button>`).join('');
  tabsEl.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      activeTabId = btn.dataset.tab;
      renderActiveTab();
    });
  });
}

controller.refresh = renderActiveTab;
controller.goTo = (tabId) => {
  activeTabId = tabId;
  renderActiveTab();
};

async function init() {
  try {
    const [pipeline, aiStatus] = await Promise.all([api.getPipeline(), api.getAiStatus()]);
    setStages(pipeline.stages);
    state.aiEnabled = aiStatus.enabled;
    const aiStatusEl = document.getElementById('aiStatus');
    aiStatusEl.textContent = `AI: ${aiStatus.enabled ? 'enabled' : 'disabled (deterministic mode)'}`;
    aiStatusEl.className = `ai-status ${aiStatus.enabled ? 'on' : 'off'}`;
  } catch (err) {
    setStatus(`Failed to reach backend API: ${err.message}`, true);
  }
  await renderActiveTab();
}

init();
