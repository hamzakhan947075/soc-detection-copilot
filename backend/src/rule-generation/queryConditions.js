'use strict';

/**
 * Maps a detection's `mitreHint` (assigned by the detection-engine behaviors)
 * to the base ECS field conditions a generated rule should filter on. This
 * keeps rule generation deterministic and tied to the actual ECS fields the
 * detection relies on, rather than inventing a query from scratch.
 */
const RULE_FILTERS = {
  brute_force: [
    { field: 'event.category', value: 'authentication' },
    { field: 'event.outcome', value: 'failure' },
  ],
  password_spraying: [
    { field: 'event.category', value: 'authentication' },
    { field: 'event.outcome', value: 'failure' },
  ],
  valid_accounts: [{ field: 'event.category', value: 'authentication' }],
  sudo_abuse: [{ field: 'process.name', value: 'sudo' }],
  create_account: [{ field: 'event.action', value: 'user_created' }],
  scheduled_task: [{ field: 'event.action', value: 'scheduled-task-created' }],
  reverse_shell: [{ field: 'event.category', value: 'process' }],
  obfuscated_files: [{ field: 'process.name', value: 'powershell.exe' }],
  powershell: [{ field: 'process.name', value: 'powershell.exe' }],
  lolbin: [{ field: 'event.category', value: 'process' }],
  credential_dumping: [{ field: 'event.category', value: 'process' }],
  service_creation: [{ field: 'event.category', value: 'process' }],
  registry_run_keys: [{ field: 'event.category', value: 'registry' }],
  network_scanning: [{ field: 'event.category', value: 'network' }],
  dns_tunneling: [
    { field: 'event.category', value: 'network' },
    { field: 'event.dataset', value: 'network.dns' },
  ],
  c2_communication: [{ field: 'event.category', value: 'network' }],
  data_exfiltration: [{ field: 'event.category', value: 'network' }],
  sql_injection: [{ field: 'event.category', value: 'web' }],
  xss: [{ field: 'event.category', value: 'web' }],
  path_traversal: [{ field: 'event.category', value: 'web' }],
  web_shell: [{ field: 'event.category', value: 'web' }],
  web_recon: [{ field: 'event.category', value: 'web' }],
};

function getConditionsFor(mitreHint) {
  return RULE_FILTERS[mitreHint] || [{ field: 'event.category', value: 'unknown' }];
}

module.exports = { RULE_FILTERS, getConditionsFor };
