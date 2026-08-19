import { api } from '../api.js';
import { state } from '../state.js';
import { escapeHtml } from '../utils.js';

export const id = 'overview';
export const label = 'Overview';

export async function render(container) {
  if (!state.sessionId) {
    container.innerHTML = `
      <div class="card">
        <h1>SOC Detection Copilot</h1>
        <p>An end-to-end SOC Analyst / Detection Engineer workspace: take raw logs exported from Elastic (or any source),
        identify the log source, discover and map fields to ECS, run detection engineering analysis, generate production
        rules (KQL / ES|QL / EQL / Lucene / Sigma), map to MITRE ATT&amp;CK, test against your data, analyze false positives,
        and tune thresholds - all before deploying.</p>
        <p class="muted">Go to the <strong>Log Ingestion</strong> tab to upload a file, paste raw events, or load a sample dataset to get started.</p>
      </div>`;
    return;
  }

  const dashboard = await api.getDashboard(state.sessionId);
  const cards = [
    ['Logs Processed', dashboard.logsProcessed],
    ['Unique Fields', dashboard.uniqueFields],
    ['ECS Mapped Fields', dashboard.ecsMappedFields],
    ['Mapping Coverage', `${dashboard.mappingCoveragePercent}%`],
    ['Detection Candidates', dashboard.detectionCandidates],
    ['Rules Generated', dashboard.rulesGenerated],
    ['Rules Validated', dashboard.rulesValidated],
    ['Potential False Positives', dashboard.potentialFalsePositives],
    ['MITRE Techniques', dashboard.mitreTechniques],
    ['High-Risk Findings', dashboard.highRiskFindings],
  ];

  container.innerHTML = `
    <h1>Detection Dashboard</h1>
    <div class="grid grid-4">
      ${cards.map(([label, value]) => `<div class="stat-card"><div class="stat-value">${escapeHtml(value)}</div><div class="stat-label">${escapeHtml(label)}</div></div>`).join('')}
    </div>

    <div class="card section-gap">
      <h2>Severity Breakdown</h2>
      <div class="grid grid-4">
        ${['critical', 'high', 'medium', 'low']
          .map(
            (sev) =>
              `<div class="stat-card"><div class="stat-value badge ${sev}" style="font-size:20px">${dashboard.severityBreakdown[sev] || 0}</div><div class="stat-label">${sev}</div></div>`
          )
          .join('')}
      </div>
    </div>

    <div class="card section-gap">
      <h2>Detected Log Source</h2>
      <p><strong>${escapeHtml(state.logSource?.source || 'Unknown')}</strong> &mdash; confidence ${escapeHtml(state.logSource?.confidence ?? 'N/A')}%</p>
      <p class="muted">${escapeHtml(state.logSource?.reason || '')}</p>
    </div>`;
}
