'use strict';

// Bounded, simple regexes only - no nested quantifiers, so there is no
// catastrophic-backtracking risk on attacker-controlled field values.
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_RE = /^[0-9a-fA-F:]{2,45}$/;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{1,24}$/;
const MAC_RE = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/;
const NUMBER_RE = /^-?\d+(\.\d+)?$/;
const PORT_RE = /^\d{1,5}$/;

function isIPv4(value) {
  if (typeof value !== 'string' || value.length > 15) return false;
  return IPV4_RE.test(value);
}

function isIPv6(value) {
  if (typeof value !== 'string' || value.length < 3 || value.length > 45) return false;
  return value.includes(':') && IPV6_RE.test(value);
}

function isIp(value) {
  return isIPv4(value) || isIPv6(value);
}

function isTimestamp(value) {
  if (value instanceof Date) return true;
  if (typeof value === 'string' && value.length <= 40) return ISO_TIMESTAMP_RE.test(value);
  if (typeof value === 'number') return value > 946684800 && value < 4102444800000; // roughly year 2000-2100
  return false;
}

function isEmail(value) {
  return typeof value === 'string' && value.length <= 320 && EMAIL_RE.test(value);
}

function isMacAddress(value) {
  return typeof value === 'string' && MAC_RE.test(value);
}

function isHostname(value) {
  return typeof value === 'string' && value.length <= 253 && HOSTNAME_RE.test(value) && value.includes('.');
}

function isPort(value) {
  const s = String(value);
  if (!PORT_RE.test(s)) return false;
  const n = Number(s);
  return n >= 0 && n <= 65535;
}

function isNumeric(value) {
  if (typeof value === 'number') return Number.isFinite(value);
  return typeof value === 'string' && value.length <= 32 && NUMBER_RE.test(value);
}

function isBoolean(value) {
  return typeof value === 'boolean' || value === 'true' || value === 'false';
}

/** Best-effort primitive type classification used across field-discovery and ECS mapping. */
function inferValueType(value) {
  if (value === null || value === undefined || value === '') return 'null';
  if (isIp(value)) return 'ip';
  if (isTimestamp(value)) return 'date';
  if (isMacAddress(value)) return 'mac';
  if (isEmail(value)) return 'email';
  if (isBoolean(value)) return 'boolean';
  if (isPort(value)) return 'port';
  if (isNumeric(value)) return 'number';
  if (isHostname(value)) return 'hostname';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'object') return 'object';
  return 'string';
}

module.exports = {
  isIp,
  isIPv4,
  isIPv6,
  isTimestamp,
  isEmail,
  isMacAddress,
  isHostname,
  isPort,
  isNumeric,
  isBoolean,
  inferValueType,
};
