import { api } from '../api.js';
import { state, setStatus } from '../state.js';
import { escapeHtml, severityBadge } from '../utils.js';
import { controller } from '../controller.js';

export const id = 'rules';
export const label = 'Rule Builder';

const RULE_TYPES = [
  ['kql', 'KQL'],
  ['esql', 'ES|QL'],
  ['eql', 'EQL'],
  ['lucene', 'Lucene'],
  ['sigma', 'Sigma'],
];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

export async function render(container) {
  if (!state.detections || state.detections.length === 0) {
    container.innerHTML = `<div class="card"><h1>Detection Rule Generator</h1><p class="muted">Run Detection Engineering analysis first to have detections available to build rules from.</p></div>`;
    return;
  }

  const selectedId = state.selectedDetectionId || state.detections[0].id;
  const detection = state.detections.find((d) => d.id === selectedId) || state.detections[0];
  const recommendedIndex = state.logSource?.recommendedDataset ? `logs-${state.logSource.recommendedDataset}-*` : 'logs-*';

  container.innerHTML = `
    <h1>Detection Rule Generator</h1>

    <div class="card">
      <div class="select-row">
        <div>
          <label>Detection Type</label>
          <select id="detectionSelect">
            ${state.detections.map((d) => `<option value="${escapeHtml(d.id)}" ${d.id === selectedId ? 'selected' : ''}>${escapeHtml(d.name)}</option>`).join('')}
          </select>
        </div>
        <div>
          <label>Platform</label>
          <select disabled><option>Elastic</option></select>
        </div>
        <div>
          <label>Rule Type</label>
          <select id="ruleTypeSelect">
            ${RULE_TYPES.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}
          </select>
        </div>
        <div>
          <label>Severity</label>
          <select id="severitySelect">
            ${SEVERITIES.map((s) => `<option value="${s}" ${s === detection.severity ? 'selected' : ''}>${s}</option>`).join('')}
          </select>
        </div>
        <div style="flex:2">
          <label>Index Pattern</label>
          <input type="text" id="indexPatternInput" value="${escapeHtml(recommendedIndex)}" />
        </div>
        <div>
          <button class="primary" id="generateBtn">Generate Rule</button>
        </div>
      </div>
    </div>

    <div id="ruleOutput"></div>

    ${
      state.rules.length > 0
        ? `<div class="card">
            <h3>Generated Rules This Session</h3>
            <div class="table-wrap"><table>
              <thead><tr><th>Rule Name</th><th>Type</th><th>Severity</th><th>Valid</th><th></th></tr></thead>
              <tbody>
                ${state.rules
                  .map(
                    (r) => `<tr>
                      <td>${escapeHtml(r.ruleName)}</td>
                      <td>${escapeHtml(r.ruleType)}</td>
                      <td>${severityBadge(r.severity)}</td>
                      <td>${r.queryValid ? '<span class="badge low">valid</span>' : '<span class="badge critical">invalid</span>'}</td>
                      <td><button class="test-rule-btn" data-id="${escapeHtml(r.ruleId)}">Test &rarr;</button></td>
                    </tr>`
                  )
                  .join('')}
              </tbody>
            </table></div>
          </div>`
        : ''
    }
  `;

  wireEvents(container);
}

function wireEvents(container) {
  container.querySelector('#detectionSelect').addEventListener('change', (e) => {
    state.selectedDetectionId = e.target.value;
  });

  container.querySelector('#generateBtn').addEventListener('click', async () => {
    const detectionId = container.querySelector('#detectionSelect').value;
    const ruleType = container.querySelector('#ruleTypeSelect').value;
    const severityOverride = container.querySelector('#severitySelect').value;
    const indexPattern = container.querySelector('#indexPatternInput').value;

    setStatus('Generating detection rule…');
    try {
      const rule = await api.createRule(state.sessionId, { detectionId, ruleType, severityOverride, indexPattern });
      state.rules.push(rule);
      state.selectedRuleId = rule.ruleId;
      renderRuleOutput(container, rule);
      setStatus(rule.queryValid ? 'Rule generated and syntax-validated.' : 'Rule generated but failed syntax validation - review before use.', !rule.queryValid);
    } catch (err) {
      setStatus(err.message, true);
    }
  });

  container.querySelectorAll('.test-rule-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.selectedRuleId = btn.dataset.id;
      controller.goTo('testing');
    });
  });
}

function renderRuleOutput(container, rule) {
  const target = container.querySelector('#ruleOutput');
  target.innerHTML = `
    <div class="card">
      <div class="detection-head">
        <h2>${escapeHtml(rule.ruleName)}</h2>
        ${severityBadge(rule.severity)}
      </div>
      <p class="muted">${escapeHtml(rule.description)}</p>
      <h3>Query (${escapeHtml(rule.ruleType.toUpperCase())})</h3>
      <pre>${escapeHtml(rule.query)}</pre>
      ${rule.queryValid ? '<div class="ok-box">Query passed syntax validation.</div>' : `<div class="error-box">Validation errors: ${rule.queryValidationErrors.map(escapeHtml).join('; ')}</div>`}

      <div class="grid grid-3 section-gap">
        <div class="stat-card"><div class="stat-value">${rule.riskScore}</div><div class="stat-label">Risk Score</div></div>
        <div class="stat-card"><div class="stat-value">${escapeHtml(rule.schedule)}</div><div class="stat-label">Schedule</div></div>
        <div class="stat-card"><div class="stat-value">${escapeHtml(rule.lookbackWindow)}</div><div class="stat-label">Lookback Window</div></div>
      </div>

      <h3 class="section-gap">Rule Structure</h3>
      <table>
        <tr><td>Data Source</td><td>${escapeHtml(rule.dataSource)}</td></tr>
        <tr><td>Index Pattern</td><td class="mono">${escapeHtml(rule.indexPattern)}</td></tr>
        <tr><td>Required Fields</td><td>${rule.requiredFields.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')}</td></tr>
        ${rule.threshold ? `<tr><td>Threshold</td><td>&ge; ${rule.threshold.count} events / ${rule.threshold.windowMinutes} min, grouped by ${rule.groupingFields.map(escapeHtml).join(', ')}</td></tr>` : ''}
        <tr><td>MITRE</td><td>${rule.mitre.techniqueId ? `${escapeHtml(rule.mitre.techniqueId)} - ${escapeHtml(rule.mitre.techniqueName)}` : 'Uncertain'}</td></tr>
      </table>

      <h3 class="section-gap">Investigation Steps</h3>
      <ol>${rule.investigationSteps.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ol>

      <button class="primary section-gap" id="proceedTestBtn">Continue to Rule Testing &rarr;</button>
    </div>`;

  target.querySelector('#proceedTestBtn').addEventListener('click', () => {
    state.selectedRuleId = rule.ruleId;
    controller.goTo('testing');
  });
}
