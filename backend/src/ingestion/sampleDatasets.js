'use strict';

const fs = require('fs');
const path = require('path');

const SAMPLE_DIR = path.join(__dirname, '..', '..', 'sample-data');

const DESCRIPTIONS = {
  ssh_auth: 'Linux SSH authentication log (system.auth) with brute-force and successful-login patterns',
  windows_security: 'Windows Security event log (winlog) with failed/successful logons',
  sysmon: 'Windows Sysmon process-creation and network events, including suspicious PowerShell',
  apache_access: 'Apache access log with normal traffic plus SQLi/path-traversal probes',
  nginx_access: 'Nginx access log with normal traffic plus XSS probes',
  firewall: 'Generic firewall/network log with allow/deny decisions and a port-scan pattern',
  dns: 'DNS query log including a DNS-tunneling-style high-entropy subdomain pattern',
  authentication_generic: 'Generic multi-application authentication log (password spraying pattern)',
};

/** Lists sample datasets available on disk, with a human description for the UI picker. */
function listSampleDatasets() {
  if (!fs.existsSync(SAMPLE_DIR)) return [];
  return fs
    .readdirSync(SAMPLE_DIR)
    .filter((f) => !f.startsWith('.'))
    .map((filename) => {
      const name = filename.replace(/\.[^.]+$/, '');
      return {
        name,
        filename,
        description: DESCRIPTIONS[name] || 'Sample dataset',
      };
    });
}

function loadSampleDataset(name) {
  const all = listSampleDatasets();
  const entry = all.find((d) => d.name === name);
  if (!entry) return null;
  const filePath = path.join(SAMPLE_DIR, entry.filename);
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(path.resolve(SAMPLE_DIR))) {
    // Defensive: never allow a crafted name to escape the sample-data directory.
    return null;
  }
  const rawText = fs.readFileSync(resolved, 'utf8');
  return { ...entry, rawText };
}

module.exports = { listSampleDatasets, loadSampleDataset };
