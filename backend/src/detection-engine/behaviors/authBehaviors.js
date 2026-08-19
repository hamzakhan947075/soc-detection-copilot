'use strict';

const { makeCandidate } = require('../candidateFactory');
const { groupBy, maxEventsInWindow } = require('../utils');

const FIVE_MIN_MS = 5 * 60 * 1000;
const PRIVILEGED_NAMES = ['root', 'administrator', 'admin', 'sa', 'domain admin', 'ec2-user'];

function detectAuthBehaviors(events) {
  const candidates = [];
  const authEvents = events.filter((e) => e.flat['event.outcome'] || e.flat['user.name']);
  if (authEvents.length === 0) return candidates;

  candidates.push(...detectBruteForce(authEvents));
  candidates.push(...detectPasswordSpraying(authEvents));
  candidates.push(...detectSuccessAfterFailures(authEvents));
  candidates.push(...detectPrivilegedAuth(authEvents));

  return candidates;
}

function detectBruteForce(events) {
  const failures = events.filter((e) => isFailure(e));
  const bySourceIp = groupBy(failures, (e) => e.flat['source.ip']);
  const candidates = [];

  for (const [ip, group] of bySourceIp.entries()) {
    if (group.length < 5) continue;
    const timestamps = group.map((e) => e.timestampMs).filter(Boolean).sort((a, b) => a - b);
    const burst = timestamps.length > 1 ? maxEventsInWindow(timestamps, FIVE_MIN_MS) : group.length;
    if (burst < 5) continue;

    const confidence = Math.min(0.98, 0.6 + burst * 0.03);
    candidates.push(
      makeCandidate({
        name: 'SSH/Authentication Brute Force',
        category: 'authentication',
        severity: burst >= 20 ? 'critical' : burst >= 10 ? 'high' : 'medium',
        confidence,
        description: `Multiple (${burst} within a 5 minute window) failed authentication attempts from source IP ${ip}.`,
        requiredFields: ['source.ip', 'user.name', 'event.action', 'event.outcome', '@timestamp'],
        mitreHint: 'brute_force',
        recommendedThreshold: { count: 10, windowMinutes: 5, groupBy: ['source.ip'] },
        matchedEventIndexes: group.map((e) => e.index),
        evidence: [`source.ip=${ip}`, `failed_attempts=${group.length}`, `max_in_5min=${burst}`],
      })
    );
  }
  return candidates;
}

function detectPasswordSpraying(events) {
  const failures = events.filter((e) => isFailure(e));
  const bySourceIp = groupBy(failures, (e) => e.flat['source.ip']);
  const candidates = [];

  for (const [ip, group] of bySourceIp.entries()) {
    const distinctUsers = new Set(group.map((e) => e.flat['user.name']).filter(Boolean));
    if (distinctUsers.size < 5) continue;

    const confidence = Math.min(0.95, 0.55 + distinctUsers.size * 0.02);
    candidates.push(
      makeCandidate({
        name: 'Password Spraying',
        category: 'authentication',
        severity: distinctUsers.size >= 15 ? 'high' : 'medium',
        confidence,
        description: `Source IP ${ip} attempted authentication against ${distinctUsers.size} distinct usernames with failures - characteristic of password spraying rather than targeted brute force.`,
        requiredFields: ['source.ip', 'user.name', 'event.outcome', '@timestamp'],
        mitreHint: 'password_spraying',
        recommendedThreshold: { count: 5, windowMinutes: 10, groupBy: ['source.ip'], distinctField: 'user.name' },
        matchedEventIndexes: group.map((e) => e.index),
        evidence: [`source.ip=${ip}`, `distinct_users=${distinctUsers.size}`],
        ruleConditions: [
          { field: 'event.category', value: 'authentication' },
          { field: 'event.outcome', value: 'failure' },
        ],
      })
    );
  }
  return candidates;
}

function detectSuccessAfterFailures(events) {
  const bySourceIp = groupBy(events, (e) => e.flat['source.ip']);
  const candidates = [];

  for (const [ip, group] of bySourceIp.entries()) {
    const sorted = group.slice().sort((a, b) => (a.timestampMs || 0) - (b.timestampMs || 0));
    const failuresBefore = [];
    for (const e of sorted) {
      if (isFailure(e)) {
        failuresBefore.push(e);
      } else if (isSuccess(e) && failuresBefore.length >= 3) {
        candidates.push(
          makeCandidate({
            name: 'Successful Authentication Following Repeated Failures',
            category: 'authentication',
            severity: 'high',
            confidence: Math.min(0.92, 0.6 + failuresBefore.length * 0.03),
            description: `Source IP ${ip} succeeded in authenticating as user "${e.flat['user.name'] || 'unknown'}" after ${failuresBefore.length} prior failures - possible successful brute force or credential compromise.`,
            requiredFields: ['source.ip', 'user.name', 'event.outcome', '@timestamp'],
            mitreHint: 'brute_force',
            recommendedThreshold: { priorFailures: 3, groupBy: ['source.ip', 'user.name'] },
            matchedEventIndexes: [...failuresBefore.map((f) => f.index), e.index],
            evidence: [`source.ip=${ip}`, `prior_failures=${failuresBefore.length}`, `user=${e.flat['user.name']}`],
          })
        );
        failuresBefore.length = 0;
      } else if (isSuccess(e)) {
        failuresBefore.length = 0;
      }
    }
  }
  return candidates;
}

function detectPrivilegedAuth(events) {
  const candidates = [];
  const privilegedEvents = events.filter((e) => {
    const user = String(e.flat['user.name'] || '').toLowerCase();
    return PRIVILEGED_NAMES.includes(user);
  });
  if (privilegedEvents.length === 0) return candidates;

  const byUser = groupBy(privilegedEvents, (e) => e.flat['user.name']);
  for (const [user, group] of byUser.entries()) {
    candidates.push(
      makeCandidate({
        name: 'Privileged Account Authentication',
        category: 'authentication',
        severity: 'medium',
        confidence: 0.75,
        description: `Authentication activity observed for privileged/high-value account "${user}" (${group.length} event(s)). Privileged logons warrant closer review regardless of outcome.`,
        requiredFields: ['user.name', 'event.outcome', 'source.ip', '@timestamp'],
        mitreHint: 'valid_accounts',
        recommendedThreshold: null,
        matchedEventIndexes: group.map((e) => e.index),
        evidence: [`user=${user}`, `events=${group.length}`],
        ruleConditions: [{ field: 'user.name', value: user }],
      })
    );
  }
  return candidates;
}

function isFailure(e) {
  const outcome = String(e.flat['event.outcome'] || '').toLowerCase();
  return outcome === 'failure' || outcome === 'fail' || outcome === 'denied';
}

function isSuccess(e) {
  const outcome = String(e.flat['event.outcome'] || '').toLowerCase();
  return outcome === 'success' || outcome === 'succeeded';
}

module.exports = { detectAuthBehaviors };
