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

function renderLoginScreen(content, onSuccess) {
  content.innerHTML = `
    <div class="card" style="max-width:360px;margin:80px auto">
      <h1>Sign in</h1>
      <p class="muted">This deployment requires a password to view or change anything.</p>
      <div class="field-row">
        <label>Password</label>
        <input type="password" id="loginPassword" autocomplete="current-password" />
      </div>
      <button class="primary" id="loginBtn">Sign in</button>
      <div id="loginError" class="section-gap"></div>
    </div>
  `;
  const submit = async () => {
    const password = content.querySelector('#loginPassword').value;
    const errorEl = content.querySelector('#loginError');
    errorEl.innerHTML = '';
    try {
      await api.login(password);
      onSuccess();
    } catch (err) {
      errorEl.innerHTML = `<div class="error-box">${err.message}</div>`;
    }
  };
  content.querySelector('#loginBtn').addEventListener('click', submit);
  content.querySelector('#loginPassword').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submit();
  });
}

async function initApp() {
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

async function init() {
  const content = document.getElementById('content');
  let authStatus;
  try {
    authStatus = await api.getAuthStatus();
  } catch (_err) {
    authStatus = { authRequired: false, authenticated: true }; // backend unreachable - initApp's own error handling will report it
  }

  if (authStatus.authRequired) {
    document.getElementById('logoutBtn').style.display = '';
    document.getElementById('logoutBtn').addEventListener('click', async () => {
      await api.logout().catch(() => {});
      location.reload();
    });
  }

  if (authStatus.authRequired && !authStatus.authenticated) {
    renderLoginScreen(content, initApp);
    return;
  }
  await initApp();
}

init();
