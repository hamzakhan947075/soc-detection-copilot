'use strict';

const { makeCandidate } = require('../candidateFactory');

const ENCODED_PS_PATTERNS = [/-enc(odedcommand)?\b/i, /-e\s+[A-Za-z0-9+/=]{20,}/i, /frombase64string/i];
const SUSPICIOUS_PS_PATTERNS = [
  /iex\s*\(/i,
  /invoke-expression/i,
  /downloadstring/i,
  /downloadfile/i,
  /-windowstyle\s+hidden/i,
  /-noprofile.*-nonint/i,
  /bypass/i,
];
const LOLBIN_PATTERNS = [/certutil.*-decode/i, /certutil.*-urlcache/i, /regsvr32.*\/i:/i, /mshta\s+http/i, /rundll32.*javascript:/i, /bitsadmin\s+\/transfer/i];
const CREDENTIAL_DUMP_PATTERNS = [/mimikatz/i, /sekurlsa/i, /lsass\.exe/i, /procdump.*lsass/i, /comsvcs\.dll.*minidump/i];

function detectWindowsBehaviors(events) {
  const candidates = [];
  candidates.push(...detectEncodedPowerShell(events));
  candidates.push(...detectSuspiciousPowerShell(events));
  candidates.push(...detectLolbins(events));
  candidates.push(...detectCredentialDumping(events));
  candidates.push(...detectServiceCreation(events));
  candidates.push(...detectScheduledTaskCreation(events));
  candidates.push(...detectRegistryPersistence(events));
  return candidates;
}

function commandText(e) {
  return `${e.flat['process.command_line'] || ''} ${e.message || ''}`;
}

function detectEncodedPowerShell(events) {
  const matches = events.filter((e) => isPowerShell(e) && ENCODED_PS_PATTERNS.some((re) => re.test(commandText(e))));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Encoded PowerShell Execution',
      category: 'windows',
      severity: 'high',
      confidence: 0.88,
      description: `Base64-encoded PowerShell command execution detected (${matches.length} event(s)) - a common technique to obscure malicious commands from logging and static detection.`,
      requiredFields: ['process.name', 'process.command_line', 'host.name', '@timestamp'],
      mitreHint: 'obfuscated_files',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(commandText(e))),
      ruleConditions: [
        { field: 'process.name', value: 'powershell.exe' },
        { field: 'process.command_line', values: ['-enc', 'encodedcommand', 'frombase64string'] },
      ],
    }),
  ];
}

function detectSuspiciousPowerShell(events) {
  const matches = events.filter((e) => isPowerShell(e) && SUSPICIOUS_PS_PATTERNS.some((re) => re.test(commandText(e))));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Suspicious PowerShell Usage',
      category: 'windows',
      severity: 'high',
      confidence: 0.78,
      description: `PowerShell invocations with download-and-execute or execution-policy-bypass characteristics observed (${matches.length} event(s)).`,
      requiredFields: ['process.name', 'process.command_line', 'host.name', '@timestamp'],
      mitreHint: 'powershell',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(commandText(e))),
      ruleConditions: [
        { field: 'process.name', value: 'powershell.exe' },
        { field: 'process.command_line', values: ['downloadstring', 'downloadfile', 'bypass', 'windowstyle hidden'] },
      ],
    }),
  ];
}

function detectLolbins(events) {
  const matches = events.filter((e) => LOLBIN_PATTERNS.some((re) => re.test(commandText(e))));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Suspicious LOLBin Usage',
      category: 'windows',
      severity: 'high',
      confidence: 0.75,
      description: `Living-off-the-land binaries (certutil, regsvr32, mshta, rundll32, bitsadmin) used in a manner consistent with payload download/execution (${matches.length} event(s)).`,
      requiredFields: ['process.name', 'process.command_line', 'host.name', '@timestamp'],
      mitreHint: 'lolbin',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(commandText(e))),
      ruleConditions: [{ field: 'process.command_line', values: ['certutil', 'regsvr32', 'mshta', 'bitsadmin'] }],
    }),
  ];
}

function detectCredentialDumping(events) {
  const matches = events.filter((e) => CREDENTIAL_DUMP_PATTERNS.some((re) => re.test(commandText(e))));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Potential Credential Dumping',
      category: 'windows',
      severity: 'critical',
      confidence: 0.85,
      description: `Command-line or process activity consistent with credential dumping tooling (Mimikatz/sekurlsa, LSASS memory access) observed (${matches.length} event(s)).`,
      requiredFields: ['process.name', 'process.command_line', 'host.name', '@timestamp'],
      mitreHint: 'credential_dumping',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(commandText(e))),
      ruleConditions: [{ field: 'process.command_line', values: ['mimikatz', 'sekurlsa', 'lsass', 'comsvcs.dll'] }],
    }),
  ];
}

function detectServiceCreation(events) {
  const matches = events.filter((e) => /sc(\.exe)?\s+create/i.test(commandText(e)) || /service was installed/i.test(e.message || ''));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Windows Service Creation',
      category: 'windows',
      severity: 'medium',
      confidence: 0.65,
      description: `New Windows service creation activity observed (${matches.length} event(s)). Attackers frequently create services for persistence or lateral execution.`,
      requiredFields: ['process.command_line', 'host.name', 'user.name', '@timestamp'],
      mitreHint: 'service_creation',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(commandText(e))),
      ruleConditions: [{ field: 'process.command_line', values: ['sc create', 'sc.exe create'] }],
    }),
  ];
}

function detectScheduledTaskCreation(events) {
  const matches = events.filter((e) => /schtasks.*\/create/i.test(commandText(e)));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Scheduled Task Creation',
      category: 'windows',
      severity: 'medium',
      confidence: 0.68,
      description: `Scheduled task creation via schtasks observed (${matches.length} event(s)) - a common persistence technique.`,
      requiredFields: ['process.command_line', 'host.name', 'user.name', '@timestamp'],
      mitreHint: 'scheduled_task',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(commandText(e))),
      ruleConditions: [{ field: 'process.command_line', value: 'schtasks' }],
    }),
  ];
}

function detectRegistryPersistence(events) {
  const matches = events.filter((e) => /\\currentversion\\run\b/i.test(commandText(e)) || /reg(\.exe)?\s+add.*\\run/i.test(commandText(e)));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Registry Run-Key Persistence',
      category: 'windows',
      severity: 'high',
      confidence: 0.8,
      description: `Modification of a Run/RunOnce registry key observed (${matches.length} event(s)) - a classic persistence mechanism.`,
      requiredFields: ['process.command_line', 'host.name', 'user.name', '@timestamp'],
      mitreHint: 'registry_run_keys',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(commandText(e))),
      ruleConditions: [{ field: 'process.command_line', value: 'currentversion' }],
    }),
  ];
}

function isPowerShell(e) {
  const proc = String(e.flat['process.name'] || '').toLowerCase();
  return proc.includes('powershell') || /powershell/i.test(e.message || '');
}

function truncate(str, max = 160) {
  if (!str) return '';
  return str.length > max ? `${str.slice(0, max)}...` : str;
}

module.exports = { detectWindowsBehaviors };
