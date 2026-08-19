'use strict';

/**
 * Deterministic, non-executing syntax validation for generated rule queries.
 * This never evaluates the query - it only inspects the text for balanced
 * delimiters, disallowed characters, and language-specific structural
 * requirements, so an invalid rule is caught before being shown to the user.
 */
function validateRule(queryText, language) {
  const errors = [];

  if (!queryText || !queryText.trim()) {
    return { valid: false, errors: ['Query is empty'] };
  }

  const balance = checkBalancedDelimiters(queryText);
  if (!balance.ok) errors.push(balance.reason);

  const dangerous = checkNoDangerousConstructs(queryText);
  if (!dangerous.ok) errors.push(dangerous.reason);

  const languageCheck = checkLanguageStructure(queryText, language);
  if (!languageCheck.ok) errors.push(languageCheck.reason);

  return { valid: errors.length === 0, errors };
}

function checkBalancedDelimiters(text) {
  const pairs = { '(': ')', '[': ']', '{': '}' };
  const closing = new Set(Object.values(pairs));
  const stack = [];
  let inQuotes = false;
  let quoteChar = null;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const prev = text[i - 1];
    if ((ch === '"' || ch === "'") && prev !== '\\') {
      if (!inQuotes) {
        inQuotes = true;
        quoteChar = ch;
      } else if (ch === quoteChar) {
        inQuotes = false;
        quoteChar = null;
      }
      continue;
    }
    if (inQuotes) continue;

    if (pairs[ch]) stack.push(pairs[ch]);
    else if (closing.has(ch)) {
      if (stack.pop() !== ch) return { ok: false, reason: `Unbalanced delimiter near position ${i} ("${ch}")` };
    }
  }

  if (inQuotes) return { ok: false, reason: 'Unterminated string literal (unbalanced quotes)' };
  if (stack.length > 0) return { ok: false, reason: 'Unbalanced parentheses/brackets/braces' };
  return { ok: true };
}

const DANGEROUS_PATTERNS = [
  { re: /;\s*(drop|delete|shutdown)\b/i, reason: 'Query contains a destructive SQL-style statement' },
  { re: /\$\{.*\}/, reason: 'Query contains template-injection syntax (${...})' },
  { re: /<script[\s>]/i, reason: 'Query contains embedded script tags' },
];

function checkNoDangerousConstructs(text) {
  for (const { re, reason } of DANGEROUS_PATTERNS) {
    if (re.test(text)) return { ok: false, reason };
  }
  return { ok: true };
}

function checkLanguageStructure(text, language) {
  switch (language) {
    case 'esql':
      if (!/^\s*FROM\s+\S+/i.test(text)) return { ok: false, reason: 'ES|QL query must start with a FROM source command' };
      return { ok: true };
    case 'eql':
      if (!/\bwhere\b/i.test(text)) return { ok: false, reason: 'EQL query must contain a WHERE clause' };
      return { ok: true };
    case 'sigma':
      if (!/detection:/.test(text) || !/condition:/.test(text)) {
        return { ok: false, reason: 'Sigma rule must contain both a detection and condition section' };
      }
      return { ok: true };
    case 'kql':
    case 'lucene':
      if (text.trim() === '*' || text.trim() === '*:*') return { ok: true };
      if (!/:/.test(text)) return { ok: false, reason: `${language.toUpperCase()} query must contain at least one field:value condition` };
      return { ok: true };
    default:
      return { ok: true };
  }
}

module.exports = { validateRule };
