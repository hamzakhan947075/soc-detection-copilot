'use strict';

const { isIPv4, isIPv6 } = require('../../field-discovery/valueTypes');
const { makeEvaluatorResult } = require('../../detections/evaluatorTypes');

/**
 * Deterministic CIDR-membership evaluator - replaces the previous
 * IPv4-only, hardcoded-RFC1918 `isPrivateIp()` heuristic with a real
 * IPv4 + IPv6 CIDR calculator over a configurable range list, and answers
 * the actual question detections need: is source/destination traffic
 * crossing an internal/external boundary.
 */

const DEFAULT_INTERNAL_IPV4_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16'];
const DEFAULT_INTERNAL_IPV6_CIDRS = ['::1/128', 'fc00::/7', 'fe80::/10'];
const DEFAULT_INTERNAL_CIDRS = [...DEFAULT_INTERNAL_IPV4_CIDRS, ...DEFAULT_INTERNAL_IPV6_CIDRS];

function ipv4ToInt(ip) {
  if (!isIPv4(ip)) return null;
  const parts = ip.split('.');
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function ipv4InCidr(ip, cidr) {
  const [base, prefixStr] = cidr.split('/');
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/** Expands an IPv6 address (including "::" shorthand and an embedded IPv4 tail) to 8 16-bit groups. */
function expandIpv6Groups(ip) {
  let addr = ip;
  const v4Tail = addr.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Tail) {
    const v4Int = ipv4ToInt(v4Tail[1]);
    if (v4Int === null) return null;
    const hi = ((v4Int >>> 16) & 0xffff).toString(16);
    const lo = (v4Int & 0xffff).toString(16);
    addr = addr.slice(0, addr.length - v4Tail[1].length) + hi + ':' + lo;
  }

  const halves = addr.split('::');
  if (halves.length > 2) return null;

  let groups;
  if (halves.length === 2) {
    const head = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const tail = halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill('0'), ...tail];
  } else {
    groups = addr.split(':');
  }
  if (groups.length !== 8) return null;

  const nums = groups.map((g) => (g === '' ? 0 : parseInt(g, 16)));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 0xffff)) return null;
  return nums;
}

function ipv6ToBigInt(ip) {
  const groups = expandIpv6Groups(ip);
  if (!groups) return null;
  let big = 0n;
  for (const g of groups) big = (big << 16n) | BigInt(g);
  return big;
}

function ipv6InCidr(ip, cidr) {
  const [base, prefixStr] = cidr.split('/');
  const prefix = prefixStr === undefined ? 128 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  const ipBig = ipv6ToBigInt(ip);
  const baseBig = ipv6ToBigInt(base);
  if (ipBig === null || baseBig === null) return false;
  if (prefix === 0) return true;
  const shift = BigInt(128 - prefix);
  const fullMask = (1n << 128n) - 1n;
  const mask = fullMask ^ ((1n << shift) - 1n);
  return (ipBig & mask) === (baseBig & mask);
}

/** True if `ip` falls inside any CIDR in `cidrList`. IPv4 and IPv6 addresses/ranges are matched independently. */
function isIpInCidrList(ip, cidrList) {
  if (!ip || !Array.isArray(cidrList)) return false;
  const ipIsV6 = ip.includes(':');
  if (ipIsV6 && !isIPv6(ip)) return false;
  if (!ipIsV6 && !isIPv4(ip)) return false;
  return cidrList.some((cidr) => {
    const cidrIsV6 = String(cidr).includes(':');
    if (ipIsV6 !== cidrIsV6) return false;
    return ipIsV6 ? ipv6InCidr(ip, cidr) : ipv4InCidr(ip, cidr);
  });
}

function isInternalIp(ip, internalCidrs = DEFAULT_INTERNAL_CIDRS) {
  return isIpInCidrList(ip, internalCidrs);
}

/**
 * Evaluates a source/destination IP pair against a configured
 * internal/external direction. Returns the shared evaluator result shape
 * (see detections/evaluatorTypes.js) so this integrates the same way any
 * other deterministic evaluator would.
 */
function evaluateCidrDirection({ sourceIp, destinationIp, internalCidrs = DEFAULT_INTERNAL_CIDRS, direction = 'internal_source_external_dest' } = {}) {
  const sourceInternal = sourceIp ? isIpInCidrList(sourceIp, internalCidrs) : null;
  const destinationInternal = destinationIp ? isIpInCidrList(destinationIp, internalCidrs) : null;

  let matched = false;
  const reasons = [];
  if (sourceIp && destinationIp) {
    if (direction === 'internal_source_external_dest') {
      matched = sourceInternal === true && destinationInternal === false;
      if (matched) reasons.push(`source.ip (${sourceIp}) is internal`, `destination.ip (${destinationIp}) is external`);
    } else if (direction === 'external_source_internal_dest') {
      matched = sourceInternal === false && destinationInternal === true;
      if (matched) reasons.push(`source.ip (${sourceIp}) is external`, `destination.ip (${destinationIp}) is internal`);
    }
  }

  return makeEvaluatorResult({
    matched,
    score: matched ? 1 : 0,
    reasons,
    evidence: { sourceIp, destinationIp, sourceInternal, destinationInternal, direction, internalCidrs },
  });
}

module.exports = {
  isIpInCidrList,
  isInternalIp,
  evaluateCidrDirection,
  DEFAULT_INTERNAL_IPV4_CIDRS,
  DEFAULT_INTERNAL_IPV6_CIDRS,
  DEFAULT_INTERNAL_CIDRS,
};
