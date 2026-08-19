'use strict';

/**
 * Investigation checklist templates keyed by detection category. These are
 * deterministic playbooks an analyst can follow immediately after a
 * detection fires - not AI-generated, since the steps are standard SOC
 * procedure regardless of the specific event content.
 */
const CHECKLISTS = {
  authentication: [
    'Identify the source IP address involved',
    'Identify the targeted username(s)',
    'Determine the total number of failed attempts and time span',
    'Check whether a successful authentication followed the failures',
    'Check the source IP reputation against threat intelligence',
    'Check the geo-location of the source IP for anomalies (impossible travel)',
    'Check for related authentication activity on other hosts from the same source',
    'Check for any process or session activity immediately following a successful logon',
    'Search for lateral movement indicators from the affected account',
    'Determine whether account compromise occurred and if credential reset is required',
  ],
  linux: [
    'Identify the host and user account involved',
    'Review the full command history/session around the event time',
    'Check parent process and how the session was established (SSH, local console, cron)',
    'Check for privilege escalation indicators (sudo, setuid binaries, /etc/passwd changes)',
    'Check for persistence artifacts (cron jobs, systemd units, new user accounts, SSH keys)',
    'Check outbound network connections initiated by the affected process',
    'Check file integrity of critical system binaries and configuration',
    'Search for the same indicators on other Linux hosts in the environment',
    'Determine whether the host requires isolation pending further analysis',
  ],
  windows: [
    'Identify the host, user account, and parent process involved',
    'Review the full process command line and any decoded/deobfuscated content',
    'Check for related Sysmon events (network connections, file writes, image loads)',
    'Check for persistence artifacts (services, scheduled tasks, run keys, WMI subscriptions)',
    'Check for credential access indicators (LSASS access, registry hive dumps)',
    'Check EDR/AV alerts correlated to the same host and time window',
    'Search for the same command line/hash across other endpoints',
    'Determine whether the host requires isolation pending further analysis',
  ],
  network: [
    'Identify the source and destination IP addresses and ports involved',
    'Check destination IP/domain reputation against threat intelligence',
    'Determine the total volume and duration of the observed traffic pattern',
    'Check DNS resolution history for the destination domain(s)',
    'Check whether the destination is expected business traffic (allowlist review)',
    'Check for the same destination contacted by other internal hosts',
    'Review packet capture or proxy logs for payload content if available',
    'Determine whether egress blocking or host isolation is warranted',
  ],
  web: [
    'Identify the source IP and targeted URL/endpoint',
    'Review the full request (method, path, query string, body if logged) for the payload',
    'Check the HTTP response code and whether the request appears to have succeeded',
    'Check for a sequence of similar requests indicating automated scanning/fuzzing',
    'Check web server and application logs for resulting errors or file changes',
    'Check whether a web shell or unexpected file was written to the web root',
    'Check source IP reputation against threat intelligence',
    'Determine whether WAF/CDN blocking rules should be added',
  ],
  firewall: [
    'Identify the source and destination IP addresses and ports involved',
    'Determine whether the source is internal or external to the network',
    'Check the firewall rule/policy that generated the log entry',
    'Check destination IP reputation against threat intelligence',
    'Check for the same source contacting multiple internal hosts (lateral scanning)',
    'Check whether the traffic pattern matches known vulnerability scanner behavior',
    'Determine whether the source should be blocked at the perimeter',
  ],
};

function getChecklist(category) {
  return CHECKLISTS[category] || CHECKLISTS.authentication;
}

module.exports = { getChecklist, CHECKLISTS };
