export function escapeHtml(value) {
  const str = value === null || value === undefined ? '' : String(value);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function severityBadge(severity) {
  const s = String(severity || 'low').toLowerCase();
  return `<span class="badge ${escapeHtml(s)}">${escapeHtml(s.toUpperCase())}</span>`;
}

export function confidenceBar(value01) {
  const pct = Math.round(Math.max(0, Math.min(1, value01)) * 100);
  return `<span class="confidence-bar"><span style="width:${pct}%"></span></span>${pct}%`;
}

export function statusBadge(status) {
  const s = String(status || 'unmapped').toLowerCase();
  return `<span class="badge ${escapeHtml(s)}">${escapeHtml(s)}</span>`;
}

