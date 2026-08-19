'use strict';

const { isKnownEcsField, isKnownEcsNamespace } = require('../ecs-mapping/ecsSchema');

/**
 * Deterministic, non-executing validation for generated rule queries. This
 * never evaluates the query - it only inspects the rendered text (for
 * balanced delimiters, disallowed characters, language-specific structural
 * requirements) and, when the structured conditions are supplied, the
 * conditions themselves (unknown/custom fields, contradictory or impossible
 * conditions, dangerous/overly-broad wildcard usage).
 *
 * Errors mean the rule cannot be trusted to mean what it claims (empty,
 * unbalanced, structurally invalid, or logically impossible to ever match).
 * Warnings mean the rule is syntactically fine but worth a second look
 * before deploying it (a custom field that may not exist in the index, a
 * leading wildcard, a query that matches everything).
 */
function validateRule(queryText, language, conditions = null) {
  const errors = [];
  const warnings = [];

  if (!queryText || !queryText.trim()) {
    return { valid: false, errors: ['Query is empty'], warnings: [] };
  }

  const balance = checkBalancedDelimiters(queryText);
  if (!balance.ok) errors.push(balance.reason);

  const dangerous = checkNoDangerousConstructs(queryText);
  if (!dangerous.ok) errors.push(dangerous.reason);

  const languageCheck = checkLanguageStructure(queryText, language);
  if (!languageCheck.ok) errors.push(languageCheck.reason);
  if (languageCheck.warning) warnings.push(languageCheck.warning);

  const wildcardWarning = checkLeadingWildcard(queryText);
  if (wildcardWarning) warnings.push(wildcardWarning);

  if (Array.isArray(conditions)) {
    const conditionErrors = checkConditionsForErrors(conditions);
    errors.push(...conditionErrors);

    const conditionWarnings = checkConditionsForWarnings(conditions);
    warnings.push(...conditionWarnings);
  }

  return { valid: errors.length === 0, errors, warnings };
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
      if (text.trim() === '*' || text.trim() === '*:*') {
        return { ok: true, warning: `${language.toUpperCase()} query is a bare match-all ("${text.trim()}") - it matches every event with no filtering at all.` };
      }
      if (!/:/.test(text)) return { ok: false, reason: `${language.toUpperCase()} query must contain at least one field:value condition` };
      return { ok: true };
    default:
      return { ok: true };
  }
}

/**
 * A wildcard at the very start of a value (e.g. field:*suffix) forces
 * Elasticsearch to scan every term - expensive and often unintentional.
 * Deliberately does not flag a bare `field:*` ("exists") check or a
 * standalone `*`/`*:*` match-all, which is a real and common pattern (the
 * bare match-all case gets its own, more specific warning above).
 */
function checkLeadingWildcard(text) {
  return /:\s*"?\*[^*"\s)]/.test(text)
    ? 'Query contains a leading wildcard (e.g. field:*value) - this forces a full-index scan and should usually be a trailing wildcard or a different field entirely.'
    : null;
}

/** Conditions that make the rule logically impossible to ever match, or reference no real filter at all. */
function checkConditionsForErrors(conditions) {
  const errors = [];

  const byField = new Map();
  for (const c of conditions) {
    if (!byField.has(c.field)) byField.set(c.field, []);
    byField.get(c.field).push(c);
  }
  for (const [field, group] of byField.entries()) {
    const exactValues = group.filter((c) => !c.exists && !c.cidr && !Array.isArray(c.values)).map((c) => String(c.value ?? '').toLowerCase());
    const distinctExact = new Set(exactValues.filter(Boolean));
    if (distinctExact.size > 1) {
      errors.push(`Contradictory conditions: "${field}" is required to equal ${[...distinctExact].map((v) => `"${v}"`).join(' AND ')} at the same time, which can never be true.`);
    }
  }

  for (const c of conditions) {
    if (c.cidr && Array.isArray(c.cidr.ranges) && c.cidr.ranges.length === 0) {
      errors.push(`Condition on "${c.field}" specifies a CIDR check with an empty range list - it can never match anything.`);
    }
    if (Array.isArray(c.values) && c.values.length === 0 && !c.exists && c.value === undefined) {
      errors.push(`Condition on "${c.field}" has an empty values list and no fallback value - it can never match anything.`);
    }
  }

  return errors;
}

/** Conditions that are valid but worth a second look - not part of ECS, or otherwise low-precision. */
function checkConditionsForWarnings(conditions) {
  const warnings = [];
  for (const c of conditions) {
    if (!isKnownEcsField(c.field) && !isKnownEcsNamespace(c.field)) {
      warnings.push(`Condition references "${c.field}", which is not an ECS field - confirm this custom field actually exists in your index before deploying.`);
    }
  }
  return warnings;
}

module.exports = { validateRule };
