'use strict';

const { buildKql, buildLucene, buildEql, buildEsql, buildSigma } = require('../src/rule-generation/queryLanguages');

const inCondition = { field: 'source.ip', cidr: { ranges: ['10.0.0.0/8', '172.16.0.0/12'], mode: 'in' } };
const notInCondition = { field: 'destination.ip', cidr: { ranges: ['10.0.0.0/8', '172.16.0.0/12'], mode: 'not_in' } };

describe('CIDR condition rendering', () => {
  test('KQL renders an "in" range as an OR of quoted CIDRs, and negates for "not_in"', () => {
    expect(buildKql([inCondition])).toBe('source.ip:("10.0.0.0/8" or "172.16.0.0/12")');
    expect(buildKql([notInCondition])).toBe('not destination.ip:("10.0.0.0/8" or "172.16.0.0/12")');
  });

  test('KQL combines an "in" source condition with a "not_in" destination condition via AND', () => {
    expect(buildKql([inCondition, notInCondition])).toBe(
      'source.ip:("10.0.0.0/8" or "172.16.0.0/12") and not destination.ip:("10.0.0.0/8" or "172.16.0.0/12")'
    );
  });

  test('Lucene renders uppercase OR/NOT', () => {
    expect(buildLucene([inCondition])).toBe('source.ip:("10.0.0.0/8" OR "172.16.0.0/12")');
    expect(buildLucene([notInCondition])).toBe('NOT destination.ip:("10.0.0.0/8" OR "172.16.0.0/12")');
  });

  test('EQL renders cidrMatch() and negates for "not_in"', () => {
    expect(buildEql([inCondition])).toBe('any where cidrMatch(source.ip, "10.0.0.0/8", "172.16.0.0/12")');
    expect(buildEql([notInCondition])).toBe('any where not cidrMatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12")');
  });

  test('ES|QL renders CIDR_MATCH() and negates for "not_in"', () => {
    const query = buildEsql([inCondition, notInCondition], 'logs-*', null);
    expect(query).toContain('CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12")');
    expect(query).toContain('NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12")');
  });

  test('Sigma renders an "in" condition with the |cidr modifier in the selection block', () => {
    const yaml = buildSigma({
      ruleName: 'Test',
      description: 'desc',
      conditions: [inCondition],
      mitre: { techniqueId: 'T1590' },
      severity: 'medium',
      logsourceCategory: 'network',
      threshold: null,
    });
    expect(yaml).toContain("source.ip|cidr:");
    expect(yaml).toContain("- '10.0.0.0/8'");
    expect(yaml).toContain('condition: selection');
  });

  test('Sigma moves a "not_in" condition into a separate filter block combined with "and not"', () => {
    const yaml = buildSigma({
      ruleName: 'Test',
      description: 'desc',
      conditions: [inCondition, notInCondition],
      mitre: { techniqueId: 'T1590' },
      severity: 'medium',
      logsourceCategory: 'network',
      threshold: null,
    });
    expect(yaml).toContain('filter:');
    expect(yaml).toContain('destination.ip|cidr:');
    expect(yaml).toContain('condition: selection and not filter');
  });

  test('a single-range CIDR condition renders without a parenthesized OR-list', () => {
    const single = { field: 'source.ip', cidr: { ranges: ['10.0.0.0/8'], mode: 'in' } };
    expect(buildKql([single])).toBe('source.ip:"10.0.0.0/8"');
    expect(buildEql([single])).toBe('any where cidrMatch(source.ip, "10.0.0.0/8")');
  });
});
