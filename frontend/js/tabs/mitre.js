import { api } from '../api.js';
import { state, setStatus } from '../state.js';
import { escapeHtml } from '../utils.js';

export const id = 'mitre';
export const label = 'MITRE ATT&CK';

export async function render(container) {
  const detections = state.detections || [];

  container.innerHTML = `
    <h1>MITRE ATT&amp;CK Mapping</h1>

    <div class="card">
      <h3>Mapped Detections In This Session</h3>
      ${
        detections.length === 0
          ? '<p class="muted">Run Detection Engineering analysis to see MITRE mappings for this dataset.</p>'
          : `<div class="table-wrap"><table>
              <thead><tr><th>Detection</th><th>Technique ID</th><th>Technique</th><th>Tactic</th><th>Confidence</th></tr></thead>
              <tbody>
                ${detections
                  .map(
                    (d) => `<tr>
                      <td>${escapeHtml(d.name)}</td>
                      <td class="mono">${d.mitre.techniqueId ? escapeHtml(d.mitre.techniqueId) : '<span class="muted">uncertain</span>'}</td>
                      <td>${escapeHtml(d.mitre.techniqueName || 'N/A')}</td>
                      <td>${escapeHtml(d.mitre.tacticName || 'N/A')}</td>
                      <td>${d.mitre.certain ? `<span class="badge low">${Math.round(d.mitre.confidence * 100)}% certain</span>` : `<span class="badge uncertain">${Math.round(d.mitre.confidence * 100)}% - review required</span>`}</td>
                    </tr>`
                  )
                  .join('')}
              </tbody>
            </table></div>`
      }
    </div>

    <div class="card section-gap">
      <h3>Full Reference Dictionary</h3>
      <p class="muted">Deterministic technique mappings this application can produce. Every mapping is explainable and static - never AI-guessed.</p>
      <div id="mitreDict" class="table-wrap"></div>
    </div>
  `;

  try {
    const dict = await api.getMitre();
    const rows = Object.entries(dict.techniques)
      .map(
        ([hint, t]) => `<tr>
        <td class="mono">${escapeHtml(hint)}</td>
        <td class="mono">${escapeHtml(t.techniqueId)}</td>
        <td>${escapeHtml(t.techniqueName)}</td>
        <td>${escapeHtml(t.tacticId)} - ${escapeHtml(t.tacticName)}</td>
        <td>${Math.round(t.confidence * 100)}%</td>
      </tr>`
      )
      .join('');
    container.querySelector('#mitreDict').innerHTML = `<table>
    <thead><tr><th>Internal Hint</th><th>Technique ID</th><th>Technique</th><th>Tactic</th><th>Base Confidence</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
  } catch (err) {
    setStatus(err.message, true);
    container.querySelector('#mitreDict').innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
  }
}
