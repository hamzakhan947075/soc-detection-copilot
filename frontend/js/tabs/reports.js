import { api } from '../api.js';
import { state, setStatus } from '../state.js';
import { escapeHtml } from '../utils.js';

export const id = 'reports';
export const label = 'Reports';

export async function render(container) {
  const rule = state.rules.find((r) => r.ruleId === state.selectedRuleId) || state.rules[state.rules.length - 1];

  if (!rule) {
    container.innerHTML = `<div class="card"><h1>Detection Engineering Report</h1><p class="muted">Generate a rule first.</p></div>`;
    return;
  }

  const report = await api.getReport(state.sessionId, rule.ruleId, 'json');

  container.innerHTML = `
    <h1>Detection Engineering Report</h1>
    <div class="card">
      <table>
        <tr><td>Detection</td><td>${escapeHtml(report.detection)}</td></tr>
        <tr><td>Log Source</td><td>${escapeHtml(report.logSource)}</td></tr>
        <tr><td>ECS Coverage</td><td>${report.ecsCoveragePercent !== null ? escapeHtml(report.ecsCoveragePercent) + '%' : 'N/A'}</td></tr>
        <tr><td>Detection Confidence</td><td>${Math.round(report.detectionConfidence * 100)}%</td></tr>
        <tr><td>MITRE</td><td>${report.mitre.techniqueId ? `${escapeHtml(report.mitre.techniqueId)} - ${escapeHtml(report.mitre.techniqueName)}` : 'Uncertain'}</td></tr>
        <tr><td>Severity</td><td>${escapeHtml(report.severity)}</td></tr>
        <tr><td>Rule Status</td><td>${escapeHtml(report.ruleStatus)}</td></tr>
        <tr><td>False Positive Risk</td><td>${escapeHtml(report.falsePositiveRisk)}</td></tr>
        <tr><td>Recommended Action</td><td><strong>${escapeHtml(report.recommendedAction)}</strong></td></tr>
      </table>

      <div class="select-row section-gap">
        <button id="exportJson">Export JSON</button>
        <button id="exportMd">Export Markdown</button>
        <button id="exportCsv">Export CSV</button>
      </div>
    </div>

    <div class="card">
      <h3>Query</h3>
      <pre>${escapeHtml(report.query)}</pre>
    </div>
  `;

  container.querySelector('#exportJson').addEventListener('click', () => exportReport('json', 'application/json', `${rule.ruleId}.json`));
  container.querySelector('#exportMd').addEventListener('click', () => exportReport('markdown', 'text/markdown', `${rule.ruleId}.md`));
  container.querySelector('#exportCsv').addEventListener('click', () => exportReport('csv', 'text/csv', `${rule.ruleId}.csv`));

  async function exportReport(format, mime, filename) {
    setStatus(`Preparing ${format} export…`);
    try {
      const content = format === 'json' ? JSON.stringify(await api.getReport(state.sessionId, rule.ruleId, 'json'), null, 2) : await api.getReport(state.sessionId, rule.ruleId, format);
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30000);
      setStatus(`Exported ${filename}.`);
    } catch (err) {
      setStatus(err.message, true);
    }
  }
}
