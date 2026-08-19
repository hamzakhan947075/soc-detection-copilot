import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, severityBadge, confidenceBar, statusBadge } from '../js/utils.js';

describe('escapeHtml', () => {
  test('escapes all five HTML-unsafe characters', () => {
    assert.equal(escapeHtml(`<script>alert("x") & 'y'</script>`), '&lt;script&gt;alert(&quot;x&quot;) &amp; &#39;y&#39;&lt;/script&gt;');
  });

  test('escapes ampersand before other entities so escaping is not double-applied', () => {
    assert.equal(escapeHtml('&lt;'), '&amp;lt;');
  });

  test('coerces null and undefined to an empty string rather than throwing', () => {
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
  });

  test('coerces non-string values via String()', () => {
    assert.equal(escapeHtml(42), '42');
    assert.equal(escapeHtml(true), 'true');
  });

  test('leaves strings with no unsafe characters unchanged', () => {
    assert.equal(escapeHtml('source.ip'), 'source.ip');
  });
});

describe('severityBadge', () => {
  test('lowercases the class and uppercases the label', () => {
    assert.equal(severityBadge('High'), '<span class="badge high">HIGH</span>');
  });

  test('defaults to "low" when given no value', () => {
    assert.equal(severityBadge(undefined), '<span class="badge low">LOW</span>');
  });

  test('escapes an attacker-controlled severity value rather than injecting it raw', () => {
    const badge = severityBadge('<img src=x onerror=alert(1)>');
    assert.ok(!badge.includes('<img'), 'raw <img tag must not appear in the output');
    assert.ok(badge.includes('&lt;img'));
  });
});

describe('statusBadge', () => {
  test('lowercases the value for both the class and the label', () => {
    assert.equal(statusBadge('Confident'), '<span class="badge confident">confident</span>');
  });

  test('defaults to "unmapped" when given no value', () => {
    assert.equal(statusBadge(null), '<span class="badge unmapped">unmapped</span>');
  });
});

describe('confidenceBar', () => {
  test('renders a proportional width and percentage for a mid-range value', () => {
    const html = confidenceBar(0.73);
    assert.ok(html.includes('width:73%'));
    assert.ok(html.includes('73%'));
  });

  test('clamps values above 1 to 100%', () => {
    assert.ok(confidenceBar(5).includes('width:100%'));
  });

  test('clamps negative values to 0%', () => {
    assert.ok(confidenceBar(-2).includes('width:0%'));
  });

  test('rounds to the nearest whole percent', () => {
    assert.ok(confidenceBar(0.333).includes('33%'));
    assert.ok(confidenceBar(0.5).includes('50%'));
  });
});
