'use strict';

const { makeCandidate } = require('../candidateFactory');

const REVERSE_SHELL_PATTERNS = [
  /\/dev\/tcp\//i,
  /nc\s+-e\s+\/bin\/(sh|bash)/i,
  /bash\s+-i\s+>&\s*\/dev\/tcp/i,
  /python[23]?\s+-c\s+.*socket/i,
  /mkfifo\s+\/tmp\//i,
];

const SUSPICIOUS_SUDO_PATTERNS = [
  /sudo.*\/bin\/(bash|sh)\s*$/i,
  /sudo.*chmod\s+(777|\+s)/i,
  /sudo.*passwd\s+root/i,
  /sudo.*visudo/i,
  /NOPASSWD/,
];

function detectLinuxBehaviors(events) {
  const candidates = [];
  candidates.push(...detectRootLogin(events));
  candidates.push(...detectSuspiciousSudo(events));
  candidates.push(...detectNewUserCreation(events));
  candidates.push(...detectCronPersistence(events));
  candidates.push(...detectReverseShell(events));
  return candidates;
}

function detectRootLogin(events) {
  const matches = events.filter((e) => {
    const user = String(e.flat['user.name'] || '').toLowerCase();
    const outcome = String(e.flat['event.outcome'] || '').toLowerCase();
    return user === 'root' && (outcome === 'success' || outcome === 'succeeded' || /accepted/i.test(e.message || ''));
  });
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Direct Root Login',
      category: 'linux',
      severity: 'high',
      confidence: 0.85,
      description: `Direct interactive login as "root" observed (${matches.length} event(s)). Direct root logins bypass individual accountability and are commonly disallowed by hardening baselines.`,
      requiredFields: ['user.name', 'event.outcome', 'source.ip', '@timestamp'],
      mitreHint: 'valid_accounts',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => `source.ip=${e.flat['source.ip'] || 'unknown'}`),
      ruleConditions: [{ field: 'user.name', value: 'root' }],
    }),
  ];
}

function detectSuspiciousSudo(events) {
  const matches = events.filter((e) => SUSPICIOUS_SUDO_PATTERNS.some((re) => re.test(e.message || '')));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Suspicious sudo Usage',
      category: 'linux',
      severity: 'high',
      confidence: 0.8,
      description: `Sudo invocations matching privilege-escalation or persistence patterns (e.g. spawning a root shell, granting NOPASSWD, editing sudoers) observed in ${matches.length} event(s).`,
      requiredFields: ['message', 'user.name', 'process.command_line', '@timestamp'],
      mitreHint: 'sudo_abuse',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(e.message)),
      ruleConditions: [{ field: 'message', values: ['sudo', 'NOPASSWD'] }],
    }),
  ];
}

function detectNewUserCreation(events) {
  const matches = events.filter((e) => /useradd|adduser|new user/i.test(e.message || ''));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'New Local User Account Created',
      category: 'linux',
      severity: 'medium',
      confidence: 0.7,
      description: `New user account creation activity detected (${matches.length} event(s)). Unexpected account creation can indicate persistence via a backdoor account.`,
      requiredFields: ['message', 'host.name', '@timestamp'],
      mitreHint: 'create_account',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(e.message)),
      ruleConditions: [{ field: 'message', values: ['useradd', 'adduser', 'new user'] }],
    }),
  ];
}

function detectCronPersistence(events) {
  const matches = events.filter((e) => /crontab|cron\.d|\/etc\/cron/i.test(e.message || ''));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Cron-Based Persistence Indicator',
      category: 'linux',
      severity: 'medium',
      confidence: 0.65,
      description: `Cron configuration changes detected (${matches.length} event(s)). Cron jobs are a common Linux persistence mechanism.`,
      requiredFields: ['message', 'host.name', 'user.name', '@timestamp'],
      mitreHint: 'scheduled_task',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(e.message)),
      ruleConditions: [{ field: 'message', values: ['crontab', 'cron.d', '/etc/cron'] }],
    }),
  ];
}

function detectReverseShell(events) {
  const matches = events.filter((e) => REVERSE_SHELL_PATTERNS.some((re) => re.test(e.message || '')));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Reverse Shell Indicator',
      category: 'linux',
      severity: 'critical',
      confidence: 0.9,
      description: `Command patterns consistent with a reverse shell (/dev/tcp redirection, netcat -e, piped interpreter sockets) observed in ${matches.length} event(s).`,
      requiredFields: ['message', 'process.command_line', 'host.name', '@timestamp'],
      mitreHint: 'reverse_shell',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(e.message)),
      ruleConditions: [{ field: 'message', values: ['/dev/tcp/', 'nc -e', 'mkfifo /tmp/'] }],
    }),
  ];
}

function truncate(str, max = 160) {
  if (!str) return '';
  return str.length > max ? `${str.slice(0, max)}...` : str;
}

module.exports = { detectLinuxBehaviors };
