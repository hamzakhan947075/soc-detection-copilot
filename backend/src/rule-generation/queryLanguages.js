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
    if (c.exists) return `${field}:*`;
    const values = valuesOf(c).map((v) => `"${escapeForQuoted(v)}"`);
    return values.length > 1 ? `${field}:(${values.join(' or ')})` : `${field}:${values[0]}`;
  });
  return clauses.length > 0 ? clauses.join(' and ') : '*';
}

function buildLucene(conditions) {
  const clauses = conditions.map((c) => {
    const field = escapeFieldName(c.field);
    if (c.exists) return `${field}:*`;
    const values = valuesOf(c).map((v) => `"${escapeForQuoted(v)}"`);
    return values.length > 1 ? `${field}:(${values.join(' OR ')})` : `${field}:${values[0]}`;
  });
  return clauses.length > 0 ? clauses.join(' AND ') : '*:*';
}

function buildEql(conditions, category = 'process') {
  const clauses = conditions.map((c) => {
    const field = escapeFieldName(c.field);
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

function buildSigma({ ruleName, description, conditions, mitre, severity, logsourceCategory, threshold }) {
  const selectionLines = conditions.map((c) => {
    const field = sigmaFieldName(c.field);
    if (c.exists) return `        ${field}: '*'`;
    const values = valuesOf(c);
    if (values.length > 1) {
      const list = values.map((v) => `\n            - "${escapeForQuoted(v)}"`).join('');
      return `        ${field}:${list}`;
    }
    return `        ${field}: "${escapeForQuoted(values[0])}"`;
  });
  const selection = selectionLines.length > 0 ? selectionLines.join('\n') : "        '*': '*'";

  const groupFields = (threshold?.groupBy || []).map(sigmaFieldName).join(', ') || 'source.ip';
  const aggregateField = threshold?.distinctField ? sigmaFieldName(threshold.distinctField) : '';
  const conditionLine = threshold
    ? `selection | count(${aggregateField}) by ${groupFields} >= ${threshold.count || 10}`
    : 'selection';

  return [
    'title: ' + yamlString(ruleName),
    'status: experimental',
    'description: ' + yamlString(description),
    'logsource:',
    `    category: ${logsourceCategory}`,
    'detection:',
    '    selection:',
    selection,
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

module.exports = { buildKql, buildLucene, buildEql, buildEsql, buildSigma, escapeForQuoted, escapeFieldName, escapeIndexPattern, valuesOf };
