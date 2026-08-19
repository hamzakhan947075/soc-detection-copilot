'use strict';

/**
 * Deterministic MITRE ATT&CK lookup table keyed by the `mitreHint` each
 * detection behavior declares. This is intentionally a static, reviewable
 * dictionary rather than an AI guess - MITRE mapping must be explainable.
 * `confidence` reflects how unambiguous the hint -> technique mapping is
 * (e.g. "brute_force" maps cleanly to T1110, but a generic hint may only
 * map to a tactic with an uncertain sub-technique).
 */
const MITRE_LOOKUP = {
  brute_force: {
    techniqueId: 'T1110.001',
    techniqueName: 'Password Guessing',
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    confidence: 0.9,
  },
  password_spraying: {
    techniqueId: 'T1110.003',
    techniqueName: 'Password Spraying',
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    confidence: 0.92,
  },
  valid_accounts: {
    techniqueId: 'T1078',
    techniqueName: 'Valid Accounts',
    tacticId: 'TA0004',
    tacticName: 'Privilege Escalation',
    confidence: 0.7,
  },
  sudo_abuse: {
    techniqueId: 'T1548.003',
    techniqueName: 'Sudo and Sudo Caching',
    tacticId: 'TA0004',
    tacticName: 'Privilege Escalation',
    confidence: 0.75,
  },
  create_account: {
    techniqueId: 'T1136.001',
    techniqueName: 'Local Account',
    tacticId: 'TA0003',
    tacticName: 'Persistence',
    confidence: 0.75,
  },
  scheduled_task: {
    techniqueId: 'T1053.005',
    techniqueName: 'Scheduled Task',
    tacticId: 'TA0003',
    tacticName: 'Persistence',
    confidence: 0.78,
  },
  reverse_shell: {
    techniqueId: 'T1059.004',
    techniqueName: 'Unix Shell',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    confidence: 0.72,
  },
  obfuscated_files: {
    techniqueId: 'T1027',
    techniqueName: 'Obfuscated Files or Information',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    confidence: 0.8,
  },
  powershell: {
    techniqueId: 'T1059.001',
    techniqueName: 'PowerShell',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    confidence: 0.82,
  },
  lolbin: {
    techniqueId: 'T1218',
    techniqueName: 'System Binary Proxy Execution',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    confidence: 0.68,
  },
  credential_dumping: {
    techniqueId: 'T1003.001',
    techniqueName: 'LSASS Memory',
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    confidence: 0.85,
  },
  service_creation: {
    techniqueId: 'T1543.003',
    techniqueName: 'Windows Service',
    tacticId: 'TA0003',
    tacticName: 'Persistence',
    confidence: 0.75,
  },
  registry_run_keys: {
    techniqueId: 'T1547.001',
    techniqueName: 'Registry Run Keys / Startup Folder',
    tacticId: 'TA0003',
    tacticName: 'Persistence',
    confidence: 0.8,
  },
  network_scanning: {
    techniqueId: 'T1046',
    techniqueName: 'Network Service Discovery',
    tacticId: 'TA0007',
    tacticName: 'Discovery',
    confidence: 0.78,
  },
  dns_tunneling: {
    techniqueId: 'T1071.004',
    techniqueName: 'DNS',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    confidence: 0.55,
  },
  c2_communication: {
    techniqueId: 'T1071',
    techniqueName: 'Application Layer Protocol',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    confidence: 0.55,
  },
  data_exfiltration: {
    techniqueId: 'T1041',
    techniqueName: 'Exfiltration Over C2 Channel',
    tacticId: 'TA0010',
    tacticName: 'Exfiltration',
    confidence: 0.5,
  },
  sql_injection: {
    techniqueId: 'T1190',
    techniqueName: 'Exploit Public-Facing Application',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    confidence: 0.7,
  },
  xss: {
    techniqueId: 'T1189',
    techniqueName: 'Drive-by Compromise',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    confidence: 0.45,
  },
  path_traversal: {
    techniqueId: 'T1190',
    techniqueName: 'Exploit Public-Facing Application',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    confidence: 0.65,
  },
  web_shell: {
    techniqueId: 'T1505.003',
    techniqueName: 'Web Shell',
    tacticId: 'TA0003',
    tacticName: 'Persistence',
    confidence: 0.75,
  },
  web_recon: {
    techniqueId: 'T1595',
    techniqueName: 'Active Scanning',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    confidence: 0.4,
  },
};

const UNCERTAIN_FLOOR = 0.6;

/** Returns the MITRE mapping for a hint, always marking low-confidence mappings as such. */
function mapToMitre(mitreHint) {
  const entry = MITRE_LOOKUP[mitreHint];
  if (!entry) {
    return {
      techniqueId: null,
      techniqueName: null,
      tacticId: null,
      tacticName: null,
      confidence: 0,
      certain: false,
      note: 'No MITRE mapping available for this detection type.',
    };
  }
  return {
    ...entry,
    certain: entry.confidence >= UNCERTAIN_FLOOR,
    note: entry.confidence >= UNCERTAIN_FLOOR ? null : 'Possible MITRE mapping - confidence below the certainty threshold; analyst review required.',
  };
}

module.exports = { mapToMitre, MITRE_LOOKUP };
