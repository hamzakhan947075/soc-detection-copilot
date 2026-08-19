'use strict';

/**
 * Renders a common set of conditions into each supported query language.
 * A condition is one of:
 *   { field, value }          - a single required substring/equality match
 *   { field, values: [...] }  - an OR match against any of several values
 *                                (detections that fire on more than one
 *                                distinct indicator, e.g. SQL injection
 *                                matched via either quote-injection or
 *                                UNION SELECT syntax)
 *   { field, exists: true }   - the field must simply be present/non-null
 *                                (used for cardinality-only signals like
 *                                port scanning, where no specific value
 *                                matters)
 *   { field, cidr: { ranges: [...], mode } } - true when the field's IP value
 *                                falls inside ('in') or outside ('not_in')
 *                                every listed CIDR range. Genuinely
 *                                expressible in all 5 languages (KQL/Lucene
 *                                IP-field term queries, EQL/ES|QL's
 *                                cidrMatch()/CIDR_MATCH(), Sigma's `|cidr`
 *                                field modifier), unlike the other
 *                                evaluator-backed signals below.
 * Any of the above may also carry `exact: true`, which only affects how
 * testing/ruleTester.js matches it against events (a substring match would
 * be a false positive for this field - e.g. an identity field like
 * user.name/process.name, or a numeric field like destination.port). It has
 * no effect on the rendered query text below, since KQL/Lucene phrase
 * matches and EQL/ES|QL `==` comparisons are already exact per-language.
 * Every value is escaped for its target language so generated queries can
 * never break out of a string literal, regardless of what characters
 * appear in a detection's evidence.
 */

function valuesOf(condition) {
  if (Array.isArray(condition.values) && condition.values.length > 0) return condition.values;
  return [condition.value];
}

function cidrRangesOf(condition) {
  return condition.cidr && Array.isArray(condition.cidr.ranges) ? condition.cidr.ranges.filter(Boolean) : [];
}

function escapeForQuoted(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function escapeFieldName(field) {
  // ECS field paths are dotted identifiers; strip anything else defensively.
  return String(field).replace(/[^a-zA-Z0-9_.]/g, '');
}

function escapeIndexPattern(index) {
  // Index patterns legitimately contain hyphens and wildcards (e.g.
  // "logs-system.auth-*"), so they get their own, more permissive escaper.
  return String(index).replace(/[^a-zA-Z0-9_.*-]/g, '');
}

function buildKql(conditions) {
  const clauses = conditions.map((c) => {
    const field = escapeFieldName(c.field);
    if (c.cidr) {
      const ranges = cidrRangesOf(c).map((r) => `"${escapeForQuoted(r)}"`);
      if (ranges.length === 0) return `${field}:*`;
      const inClause = ranges.length > 1 ? `${field}:(${ranges.join(' or ')})` : `${field}:${ranges[0]}`;
      return c.cidr.mode === 'not_in' ? `not ${inClause}` : inClause;
    }
    if (c.exists) return `${field}:*`;
    const values = valuesOf(c).map((v) => `"${escapeForQuoted(v)}"`);
    return values.length > 1 ? `${field}:(${values.join(' or ')})` : `${field}:${values[0]}`;
  });
  return clauses.length > 0 ? clauses.join(' and ') : '*';
}

function buildLucene(conditions) {
  const clauses = conditions.map((c) => {
    const field = escapeFieldName(c.field);
    if (c.cidr) {
      const ranges = cidrRangesOf(c).map((r) => `"${escapeForQuoted(r)}"`);
      if (ranges.length === 0) return `${field}:*`;
      const inClause = ranges.length > 1 ? `${field}:(${ranges.join(' OR ')})` : `${field}:${ranges[0]}`;
      return c.cidr.mode === 'not_in' ? `NOT ${inClause}` : inClause;
    }
    if (c.exists) return `${field}:*`;
    const values = valuesOf(c).map((v) => `"${escapeForQuoted(v)}"`);
    return values.length > 1 ? `${field}:(${values.join(' OR ')})` : `${field}:${values[0]}`;
  });
  return clauses.length > 0 ? clauses.join(' AND ') : '*:*';
}

function buildEql(conditions, category = 'process') {
  const clauses = conditions.map((c) => {
    const field = escapeFieldName(c.field);
    if (c.cidr) {
      const ranges = cidrRangesOf(c).map((r) => `"${escapeForQuoted(r)}"`);
      if (ranges.length === 0) return `${field} != null`;
      const call = `cidrMatch(${field}, ${ranges.join(', ')})`;
      return c.cidr.mode === 'not_in' ? `not ${call}` : call;
    }
    if (c.exists) return `${field} != null`;
    const values = valuesOf(c);
    const eqs = values.map((v) => `${field} == "${escapeForQuoted(v)}"`);
    return eqs.length > 1 ? `(${eqs.join(' or ')})` : eqs[0];
  });
  if (clauses.length === 0) {
    return `any where ${escapeFieldName('event.category')} == "${escapeForQuoted(category)}"`;
  }
  return `any where ${clauses.join(' and ')}`;
}

function buildEsql(conditions, index, threshold) {
  const clauses = conditions.map((c) => {
    const field = escapeFieldName(c.field);
    if (c.cidr) {
      const ranges = cidrRangesOf(c).map((r) => `"${escapeForQuoted(r)}"`);
      if (ranges.length === 0) return `${field} IS NOT NULL`;
      const call = `CIDR_MATCH(${field}, ${ranges.join(', ')})`;
      return c.cidr.mode === 'not_in' ? `NOT ${call}` : call;
    }
    if (c.exists) return `${field} IS NOT NULL`;
    const values = valuesOf(c);
    const eqs = values.map((v) => `${field} == "${escapeForQuoted(v)}"`);
    return eqs.length > 1 ? `(${eqs.join(' OR ')})` : eqs[0];
  });
  let query = `FROM ${escapeIndexPattern(index)}`;
  if (clauses.length > 0) query += `\n| WHERE ${clauses.join(' AND ')}`;

  if (threshold && threshold.groupBy && threshold.groupBy.length > 0) {
    const groupFields = threshold.groupBy.map(escapeFieldName);
    if (groupFields.length > 0) {
      const aggregate = threshold.distinctField
        ? `COUNT_DISTINCT(${escapeFieldName(threshold.distinctField)})`
        : 'COUNT(*)';
      query += `\n| STATS event_count = ${aggregate} BY ${groupFields.join(', ')}`;
      query += `\n| WHERE event_count >= ${Number(threshold.count) || 10}`;
    }
  }
  return query;
}

function sigmaConditionLine(c) {
  const field = sigmaFieldName(c.field);
  if (c.cidr) {
    const ranges = cidrRangesOf(c);
    if (ranges.length === 0) return `        ${field}: '*'`;
    if (ranges.length === 1) return `        ${field}|cidr: '${escapeForQuoted(ranges[0])}'`;
    const list = ranges.map((r) => `\n            - '${escapeForQuoted(r)}'`).join('');
    return `        ${field}|cidr:${list}`;
  }
  if (c.exists) return `        ${field}: '*'`;
  const values = valuesOf(c);
  if (values.length > 1) {
    const list = values.map((v) => `\n            - "${escapeForQuoted(v)}"`).join('');
    return `        ${field}:${list}`;
  }
  return `        ${field}: "${escapeForQuoted(values[0])}"`;
}

function buildSigma({ ruleName, description, conditions, mitre, severity, logsourceCategory, threshold }) {
  // A plain Sigma selection block is an implicit AND-of-equals - there's no
  // per-field "not" modifier, so a `cidr: {mode: 'not_in'}` condition (e.g.
  // "destination is not internal") needs its own `filter` block, combined
  // via `selection and not filter`, per Sigma's standard exclusion pattern.
  const exclusionConditions = conditions.filter((c) => c.cidr && c.cidr.mode === 'not_in');
  const positiveConditions = conditions.filter((c) => !(c.cidr && c.cidr.mode === 'not_in'));

  const selectionLines = positiveConditions.map(sigmaConditionLine);
  const selection = selectionLines.length > 0 ? selectionLines.join('\n') : "        '*': '*'";

  const detectionLines = ['    selection:', selection];
  let conditionExpr = 'selection';
  if (exclusionConditions.length > 0) {
    detectionLines.push('    filter:', exclusionConditions.map(sigmaConditionLine).join('\n'));
    conditionExpr = 'selection and not filter';
  }

  const groupFields = (threshold?.groupBy || []).map(sigmaFieldName).join(', ') || 'source.ip';
  const aggregateField = threshold?.distinctField ? sigmaFieldName(threshold.distinctField) : '';
  const conditionLine = threshold
    ? `${conditionExpr} | count(${aggregateField}) by ${groupFields} >= ${threshold.count || 10}`
    : conditionExpr;

  return [
    'title: ' + yamlString(ruleName),
    'status: experimental',
    'description: ' + yamlString(description),
    'logsource:',
    `    category: ${logsourceCategory}`,
    'detection:',
    ...detectionLines,
    `    condition: ${conditionLine}`,
    `level: ${sigmaLevel(severity)}`,
    'tags:',
    mitre && mitre.techniqueId ? `    - attack.${mitre.techniqueId.toLowerCase()}` : '    - attack.unknown',
  ].join('\n');
}

function sigmaFieldName(field) {
  return escapeFieldName(field);
}

function yamlString(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function sigmaLevel(severity) {
  const map = { low: 'low', medium: 'medium', high: 'high', critical: 'critical' };
  return map[severity] || 'medium';
}

module.exports = { buildKql, buildLucene, buildEql, buildEsql, buildSigma, escapeForQuoted, escapeFieldName, escapeIndexPattern, valuesOf, cidrRangesOf };
