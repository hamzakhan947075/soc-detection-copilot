'use strict';

/**
 * Static, deterministic false-positive guidance per detection type. This is
 * general SOC knowledge (not computed from the analyst's actual data) shown
 * alongside the dynamic false-positive analysis produced by fpAnalysis.js
 * after a rule is tested against real events.
 */
const FP_GUIDANCE = {
  brute_force: {
    scenarios: ['Vulnerability scanners or pentest tools generating repeated auth failures', 'Misconfigured application/service retrying with a stale credential'],
    recommendedExclusions: ['Exclude known scanner/monitoring IP ranges (requires analyst approval)', 'Exclude known service accounts with documented retry behavior'],
  },
  password_spraying: {
    scenarios: ['Password-reset self-service tools testing multiple accounts', 'Security awareness/phishing simulation platforms'],
    recommendedExclusions: ['Exclude documented internal testing source IPs (requires analyst approval)'],
  },
  valid_accounts: {
    scenarios: ['Scheduled maintenance performed under a privileged account', 'Automation/service accounts intentionally named after privileged roles'],
    recommendedExclusions: ['Exclude documented maintenance windows or automation source hosts'],
  },
  sudo_abuse: {
    scenarios: ['Legitimate administrative scripts invoking sudo with broad permissions', 'Configuration management tools (Ansible/Chef/Puppet) using sudo'],
    recommendedExclusions: ['Exclude known configuration-management source processes/users'],
  },
  create_account: {
    scenarios: ['Routine onboarding automation creating new accounts', 'IT provisioning scripts'],
    recommendedExclusions: ['Exclude accounts created by the approved provisioning service account'],
  },
  scheduled_task: {
    scenarios: ['Legitimate scheduled maintenance or backup jobs', 'Software installers registering update tasks'],
    recommendedExclusions: ['Exclude tasks created by approved software deployment tools'],
  },
  reverse_shell: {
    scenarios: ['Legitimate remote administration tooling using similar syntax', 'Security testing / red team activity in an authorized engagement'],
    recommendedExclusions: ['Exclude hosts under an active, approved penetration test'],
  },
  obfuscated_files: {
    scenarios: ['Legitimate PowerShell modules that base64-encode payloads for transport', 'Software deployment tools using encoded commands'],
    recommendedExclusions: ['Exclude known internal automation scripts after verifying their content'],
  },
  powershell: {
    scenarios: ['Administrators using remote management scripts with bypass flags', 'Software deployment via PowerShell DSC'],
    recommendedExclusions: ['Exclude approved administrative scripts run by known service accounts'],
  },
  lolbin: {
    scenarios: ['IT deploying certificates or DLLs via legitimate admin workflows'],
    recommendedExclusions: ['Exclude documented software deployment processes using these binaries'],
  },
  credential_dumping: {
    scenarios: ['Authorized red team / purple team credential access testing', 'EDR/AV engine self-testing'],
    recommendedExclusions: ['Exclude hosts under an active, approved security assessment'],
  },
  service_creation: {
    scenarios: ['Software installers registering a new Windows service'],
    recommendedExclusions: ['Exclude services created by approved software deployment tools'],
  },
  registry_run_keys: {
    scenarios: ['Legitimate software configuring itself to start at login'],
    recommendedExclusions: ['Exclude known, approved software installers'],
  },
  network_scanning: {
    scenarios: ['Authorized vulnerability scanning (Nessus/Qualys/Rapid7)', 'Internal asset-discovery tooling'],
    recommendedExclusions: ['Exclude approved vulnerability scanner IP ranges (requires analyst approval)'],
  },
  dns_tunneling: {
    scenarios: ['CDN/cloud provider health-check subdomains with long random labels', 'Legitimate anti-malware/threat-intel feeds using DNS-based lookups'],
    recommendedExclusions: ['Exclude known CDN/cloud provider domains after validation'],
  },
  c2_communication: {
    scenarios: ['Legitimate application heartbeats/polling to a SaaS API on a regular interval'],
    recommendedExclusions: ['Exclude verified, approved SaaS/API destinations'],
  },
  data_exfiltration: {
    scenarios: ['Scheduled backup jobs transferring large volumes to cloud storage'],
    recommendedExclusions: ['Exclude approved backup destinations and schedules'],
  },
  sql_injection: {
    scenarios: ['Automated security scanners/DAST tools testing the same application'],
    recommendedExclusions: ['Exclude approved DAST/scanner source IPs'],
  },
  xss: {
    scenarios: ['Automated security scanners testing for reflected input handling'],
    recommendedExclusions: ['Exclude approved DAST/scanner source IPs'],
  },
  path_traversal: {
    scenarios: ['Automated security scanners probing for traversal vulnerabilities'],
    recommendedExclusions: ['Exclude approved DAST/scanner source IPs'],
  },
  web_shell: {
    scenarios: ['Legitimate administrative file manager tools with similar file naming'],
    recommendedExclusions: ['Exclude verified, approved administrative tooling paths'],
  },
  web_recon: {
    scenarios: ['REST APIs legitimately using PUT/DELETE methods', 'Health-check/monitoring tools'],
    recommendedExclusions: ['Exclude documented API clients and monitoring sources'],
  },
};

const DEFAULT_GUIDANCE = {
  scenarios: ['Insufficient historical data to characterize false-positive sources for this detection type yet.'],
  recommendedExclusions: ['Review matched events manually before creating any exclusion.'],
};

function getFpGuidance(mitreHint) {
  return FP_GUIDANCE[mitreHint] || DEFAULT_GUIDANCE;
}

module.exports = { getFpGuidance };
