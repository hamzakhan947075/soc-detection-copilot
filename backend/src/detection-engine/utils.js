'use strict';

const { isIPv4 } = require('../field-discovery/valueTypes');

function toEpochMs(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return value > 1e12 ? value : value * 1000;
  const d = new Date(value);
  const t = d.getTime();
  return Number.isNaN(t) ? null : t;
}

/** Groups items by a key function, skipping items where the key is empty. */
function groupBy(items, keyFn) {
  const groups = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (key === null || key === undefined || key === '') continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return groups;
}

/**
 * Given a sorted-by-time array of epoch ms timestamps, returns the maximum
 * number of events whose timestamps fall inside any window of `windowMs`
 * width (sliding window count) - used for threshold-style detections like
 * "N failures within 5 minutes".
 */
function maxEventsInWindow(sortedTimestamps, windowMs) {
  let maxCount = 1;
  let left = 0;
  for (let right = 0; right < sortedTimestamps.length; right++) {
    while (sortedTimestamps[right] - sortedTimestamps[left] > windowMs) {
      left++;
    }
    maxCount = Math.max(maxCount, right - left + 1);
  }
  return maxCount;
}

const PRIVATE_IPV4_RANGES = [
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^127\./,
];

function isPrivateIp(ip) {
  if (!isIPv4(ip)) return false;
  return PRIVATE_IPV4_RANGES.some((re) => re.test(ip));
}

/** Shannon entropy of a string, used as one signal (not the sole signal) for DNS tunneling. */
function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum + p * Math.log2(p);
  }, 0);
}

module.exports = { toEpochMs, groupBy, maxEventsInWindow, isPrivateIp, shannonEntropy };
