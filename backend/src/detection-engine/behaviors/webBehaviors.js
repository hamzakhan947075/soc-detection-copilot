'use strict';

const { makeCandidate } = require('../candidateFactory');

const SQLI_PATTERNS = [/(\%27)|(')|(--)|(\%23)|(#)/i, /union(\s|\%20)+select/i, /or\s+1\s*=\s*1/i, /select.+from.+information_schema/i, /sleep\(\d+\)/i];
const XSS_PATTERNS = [/<script[\s>]/i, /onerror\s*=/i, /onload\s*=/i, /javascript:/i, /<img[^>]+src[^>]*onerror/i];
const PATH_TRAVERSAL_PATTERNS = [/\.\.\/\.\.\//, /%2e%2e%2f/i, /\.\.\\\.\.\\/, /etc\/passwd/i, /boot\.ini/i];
const WEBSHELL_PATTERNS = [/\b(cmd|shell|c99|r57|webshell)\.(php|asp|aspx|jsp)\b/i, /eval\(\s*\$_(get|post|request)/i, /system\(\s*\$_(get|post|request)/i];
const SUSPICIOUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT'];

function detectWebBehaviors(events) {
  const webEvents = events.filter((e) => e.flat['url.original'] || e.flat['url.path'] || e.flat['http.request.method']);
  if (webEvents.length === 0) return [];

  const candidates = [];
  candidates.push(...matchPattern(webEvents, SQLI_PATTERNS, 'SQL Injection Attempt', 'critical', 0.75, 'sql_injection',
    'HTTP request field(s) contain SQL-injection-characteristic syntax (quotes, UNION SELECT, boolean tautologies, information_schema references).',
    ["'", '--', 'union select', 'or 1=1', 'information_schema']));
  candidates.push(...matchPattern(webEvents, XSS_PATTERNS, 'Cross-Site Scripting (XSS) Attempt', 'high', 0.7, 'xss',
    'HTTP request field(s) contain script tags or inline event-handler injection characteristic of XSS.',
    ['<script', 'onerror=', 'onload=', 'javascript:']));
  candidates.push(...matchPattern(webEvents, PATH_TRAVERSAL_PATTERNS, 'Path Traversal Attempt', 'high', 0.75, 'path_traversal',
    'HTTP request field(s) contain directory traversal sequences or references to sensitive OS files.',
    ['../../', '%2e%2e%2f', 'etc/passwd', 'boot.ini']));
  candidates.push(...matchPattern(webEvents, WEBSHELL_PATTERNS, 'Possible Web Shell Access', 'critical', 0.7, 'web_shell',
    'Request path/parameters match common web shell filenames or dynamic code execution via user input.',
    ['shell.php', 'cmd.php', 'c99.php', 'r57.php']));
  candidates.push(...detectSuspiciousMethods(webEvents));
  candidates.push(...detectAuthAbuse(webEvents));

  return candidates;
}

function requestText(e) {
  return [e.flat['url.original'], e.flat['url.path'], e.flat['url.query'], e.message].filter(Boolean).join(' ');
}

function matchPattern(events, patterns, name, severity, confidence, mitreHint, description, ruleConditionValues) {
  const matches = events.filter((e) => patterns.some((re) => re.test(requestText(e))));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name,
      category: 'web',
      severity,
      confidence,
      description: `${description} (${matches.length} matching request(s)).`,
      requiredFields: ['url.original', 'source.ip', 'http.request.method', '@timestamp'],
      mitreHint,
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => truncate(requestText(e))),
      // Approximation: the underlying regex family covers several distinct
      // payload shapes (see the *_PATTERNS constants above); the generated
      // rule condition below OR-matches the most common literal indicators
      // rather than reproducing the full regex, so it stays a safe
      // substring match. Analysts should broaden this before production use
      // if their traffic uses a payload variant not listed here.
      ruleConditions: [{ field: 'url.original', values: ruleConditionValues }],
    }),
  ];
}

function detectSuspiciousMethods(events) {
  const matches = events.filter((e) => SUSPICIOUS_METHODS.includes(String(e.flat['http.request.method'] || '').toUpperCase()));
  if (matches.length === 0) return [];
  return [
    makeCandidate({
      name: 'Suspicious HTTP Method Usage',
      category: 'web',
      severity: 'medium',
      confidence: 0.55,
      description: `Requests using uncommon/high-risk HTTP methods (PUT, DELETE, TRACE, CONNECT) observed (${matches.length} event(s)); may indicate reconnaissance or unauthorized content modification attempts.`,
      requiredFields: ['http.request.method', 'url.original', 'source.ip', '@timestamp'],
      mitreHint: 'web_recon',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => `${e.flat['http.request.method']} ${e.flat['url.original'] || e.flat['url.path'] || ''}`),
      ruleConditions: [{ field: 'http.request.method', values: SUSPICIOUS_METHODS }],
    }),
  ];
}

function detectAuthAbuse(events) {
  const matches = events.filter((e) => {
    const status = Number(e.flat['http.response.status_code']);
    const path = String(e.flat['url.path'] || '').toLowerCase();
    return status === 401 || status === 403 || (path.includes('login') && status >= 400);
  });
  if (matches.length < 5) return [];
  return [
    makeCandidate({
      name: 'Web Authentication Abuse',
      category: 'web',
      severity: 'medium',
      confidence: 0.6,
      description: `${matches.length} HTTP 401/403 responses observed against authentication endpoints - possible credential brute forcing against a web application login form.`,
      requiredFields: ['url.path', 'http.response.status_code', 'source.ip', '@timestamp'],
      mitreHint: 'brute_force',
      matchedEventIndexes: matches.map((e) => e.index),
      evidence: matches.slice(0, 5).map((e) => `${e.flat['source.ip']} ${e.flat['url.path']} -> ${e.flat['http.response.status_code']}`),
      ruleConditions: [{ field: 'http.response.status_code', values: ['401', '403'], exact: true }],
    }),
  ];
}

function truncate(str, max = 160) {
  if (!str) return '';
  return str.length > max ? `${str.slice(0, max)}...` : str;
}

module.exports = { detectWebBehaviors };
