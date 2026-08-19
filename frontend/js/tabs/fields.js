import { state } from '../state.js';
import { escapeHtml, confidenceBar, statusBadge } from '../utils.js';
import { controller } from '../controller.js';

export const id = 'fields';
export const label = 'Field Discovery';

export async function render(container) {
  if (!state.sessionId) {
    container.innerHTML = emptyState();
    return;
  }

  const ls = state.logSource;
  const fd = state.fieldDiscovery;

  container.innerHTML = `
    <h1>Field Discovery</h1>

    <div class="card">
      <h3>Detected Log Source</h3>
      <p><strong style="font-size:16px">${escapeHtml(ls.source)}</strong> &nbsp; ${confidenceBar((ls.confidence || 0) / 100)}</p>
      <p class="muted"><strong>Evidence:</strong> ${escapeHtml(ls.reason)}</p>
      ${ls.recommendedDataset ? `<p class="muted"><strong>Recommended Dataset:</strong> <code>${escapeHtml(ls.recommendedDataset)}</code></p>` : ''}
      <p class="muted"><strong>Important Fields:</strong> ${(ls.importantFields || []).map((f) => `<code>${escapeHtml(f)}</code>`).join(', ')}</p>
      ${
        Array.isArray(ls.candidates) && ls.candidates.length > 1
          ? `<h3 class="section-gap">Other Possible Sources</h3>
             <p class="muted">Log source identification is a confidence-scored heuristic, never a certainty - every candidate that was considered is shown below, not just the winner.</p>
             <div class="table-wrap">
               <table>
                 <thead><tr><th>Source</th><th>Confidence</th><th>Evidence</th></tr></thead>
                 <tbody>
                   ${ls.candidates
                     .map(
                       (c) => `<tr>
                         <td>${escapeHtml(c.source)}</td>
                         <td>${confidenceBar((c.confidence || 0) / 100)}</td>
                         <td class="muted">${(c.matchedReasons || []).map((r) => escapeHtml(r)).join('; ')}</td>
                       </tr>`
                     )
                     .join('')}
                 </tbody>
               </table>
             </div>`
          : ''
      }
    </div>

    <div class="card">
      <h3>Discovered Fields (${fd.uniqueFieldCount} unique / ${fd.totalEvents} events)</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Raw Field</th><th>Type</th><th>Example</th><th>Frequency</th><th>Null %</th><th>Security Relevance</th><th>ECS Candidate</th><th>Confidence</th></tr>
          </thead>
          <tbody>
            ${fd.fields
              .map(
                (f) => `<tr>
                  <td class="mono">${escapeHtml(f.field)}</td>
                  <td>${escapeHtml(f.type)}</td>
                  <td class="mono">${escapeHtml(JSON.stringify(f.exampleValues[0] ?? ''))}</td>
                  <td>${escapeHtml(f.frequency)}%</td>
                  <td>${escapeHtml(f.nullPercentage)}%</td>
                  <td>${escapeHtml(f.securityRelevance)}</td>
                  <td class="mono">${f.ecsCandidate ? escapeHtml(f.ecsCandidate) : '<span class="muted">none</span>'}</td>
                  <td>${f.ecsCandidate ? confidenceBar(f.ecsConfidence) : statusBadge(f.ecsStatus)}</td>
                </tr>`
              )
              .join('')}
          </tbody>
        </table>
      </div>
    </div>

    <button class="primary" id="toMappingBtn">Continue to ECS Mapping &rarr;</button>
  `;

  container.querySelector('#toMappingBtn').addEventListener('click', () => controller.goTo('ecs'));
}

function emptyState() {
  return `<div class="card"><h1>Field Discovery</h1><p class="muted">Ingest a dataset first from the Log Ingestion tab.</p></div>`;
}
