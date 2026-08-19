'use strict';

/**
 * A curated subset of the Elastic Common Schema (ECS) covering the field
 * families this application actively maps to. Each entry documents the
 * canonical ECS field, its ECS data type, and a human description used in
 * mapping-reason text. This is intentionally data, not code, so it is easy
 * to extend without touching mapping logic.
 */
const ECS_FIELDS = {
  '@timestamp': { type: 'date', description: 'Date/time when the event originated' },
  'message': { type: 'match_only_text', description: 'Free-text log message' },

  'event.category': { type: 'keyword', description: 'High level event category (authentication, network, ...)' },
  'event.type': { type: 'keyword', description: 'Sub-categorization of the event (start, end, denied, ...)' },
  'event.action': { type: 'keyword', description: 'The action captured by the event' },
  'event.outcome': { type: 'keyword', description: 'Outcome of the event (success, failure, unknown)' },
  'event.dataset': { type: 'keyword', description: 'Dataset the event came from' },
  'event.module': { type: 'keyword', description: 'Module/integration that produced the event' },
  'event.severity': { type: 'long', description: 'Numeric severity of the event' },
  'event.original': { type: 'keyword', description: 'Raw original event text' },
  'event.id': { type: 'keyword', description: 'Unique identifier for the event' },

  'host.name': { type: 'keyword', description: 'Hostname of the host' },
  'host.hostname': { type: 'keyword', description: 'Hostname as reported by the host' },
  'host.ip': { type: 'ip', description: 'IP addresses of the host' },
  'host.os.name': { type: 'keyword', description: 'Operating system name' },

  'source.ip': { type: 'ip', description: 'IP address of the source of the event' },
  'source.port': { type: 'long', description: 'Source port' },
  'source.domain': { type: 'keyword', description: 'Source domain name' },
  'source.address': { type: 'keyword', description: 'Source network address' },
  'source.geo.country_name': { type: 'keyword', description: 'Source geo country' },
  'source.bytes': { type: 'long', description: 'Bytes sent from the source' },

  'destination.ip': { type: 'ip', description: 'IP address of the destination of the event' },
  'destination.port': { type: 'long', description: 'Destination port' },
  'destination.domain': { type: 'keyword', description: 'Destination domain name' },
  'destination.address': { type: 'keyword', description: 'Destination network address' },
  'destination.bytes': { type: 'long', description: 'Bytes sent to the destination' },

  'client.ip': { type: 'ip', description: 'IP address of the client' },
  'client.port': { type: 'long', description: 'Client port' },
  'server.ip': { type: 'ip', description: 'IP address of the server' },
  'server.port': { type: 'long', description: 'Server port' },

  'network.protocol': { type: 'keyword', description: 'Application layer protocol' },
  'network.transport': { type: 'keyword', description: 'Transport layer protocol (tcp/udp)' },
  'network.direction': { type: 'keyword', description: 'Direction of the network traffic' },
  'network.bytes': { type: 'long', description: 'Total bytes transferred' },

  'user.name': { type: 'keyword', description: 'Short login name / username of the user' },
  'user.id': { type: 'keyword', description: 'Unique identifier of the user' },
  'user.domain': { type: 'keyword', description: 'Domain the user belongs to' },
  'user.roles': { type: 'keyword', description: 'Roles/groups assigned to the user' },
  'user.target.name': { type: 'keyword', description: 'Target/impersonated username of the event' },

  'process.name': { type: 'keyword', description: 'Process name' },
  'process.command_line': { type: 'wildcard', description: 'Full command line of the process' },
  'process.pid': { type: 'long', description: 'Process ID' },
  'process.parent.name': { type: 'keyword', description: 'Parent process name' },
  'process.executable': { type: 'keyword', description: 'Absolute path to the process executable' },
  'process.args': { type: 'keyword', description: 'Process command-line arguments' },

  'file.path': { type: 'keyword', description: 'Full path of the file' },
  'file.name': { type: 'keyword', description: 'Name of the file' },
  'file.hash.sha256': { type: 'keyword', description: 'SHA-256 hash of the file' },
  'file.extension': { type: 'keyword', description: 'File extension' },

  'url.original': { type: 'wildcard', description: 'Full unparsed URL' },
  'url.path': { type: 'wildcard', description: 'Path of the request' },
  'url.query': { type: 'keyword', description: 'Query string of the request' },
  'url.domain': { type: 'keyword', description: 'Domain of the URL' },

  'http.request.method': { type: 'keyword', description: 'HTTP request method' },
  'http.response.status_code': { type: 'long', description: 'HTTP response status code' },
  'http.request.referrer': { type: 'keyword', description: 'HTTP referrer' },
  'user_agent.original': { type: 'keyword', description: 'Unparsed user agent string' },

  'dns.question.name': { type: 'keyword', description: 'DNS query name' },
  'dns.question.type': { type: 'keyword', description: 'DNS record type queried' },
  'dns.response_code': { type: 'keyword', description: 'DNS response code' },

  'observer.name': { type: 'keyword', description: 'Name of the observing sensor/device' },
  'observer.vendor': { type: 'keyword', description: 'Vendor of the observing device' },
  'observer.product': { type: 'keyword', description: 'Product name of the observing device' },

  'rule.name': { type: 'keyword', description: 'Name of the rule/signature that triggered' },
  'rule.id': { type: 'keyword', description: 'Identifier of the rule/signature that triggered' },

  'related.ip': { type: 'ip', description: 'All IPs related to the event' },
  'related.user': { type: 'keyword', description: 'All usernames related to the event' },
  'related.hosts': { type: 'keyword', description: 'All hostnames related to the event' },

  'threat.technique.id': { type: 'keyword', description: 'MITRE ATT&CK technique ID' },
  'threat.technique.name': { type: 'keyword', description: 'MITRE ATT&CK technique name' },
  'threat.tactic.id': { type: 'keyword', description: 'MITRE ATT&CK tactic ID' },
  'threat.tactic.name': { type: 'keyword', description: 'MITRE ATT&CK tactic name' },

  'cloud.provider': { type: 'keyword', description: 'Cloud provider name' },
  'cloud.region': { type: 'keyword', description: 'Cloud region' },
  'cloud.account.id': { type: 'keyword', description: 'Cloud account identifier' },

  'service.name': { type: 'keyword', description: 'Name of the service' },
  'service.type': { type: 'keyword', description: 'Type of the service' },

  'agent.type': { type: 'keyword', description: 'Type of agent that shipped the event' },
  'agent.version': { type: 'keyword', description: 'Version of the shipping agent' },

  'log.level': { type: 'keyword', description: 'Log level of the message' },
  'log.original': { type: 'keyword', description: 'Original raw log line' },
  'log.file.path': { type: 'keyword', description: 'Path to the log file' },
};

function isKnownEcsField(field) {
  return Object.prototype.hasOwnProperty.call(ECS_FIELDS, field);
}

function getEcsFieldInfo(field) {
  return ECS_FIELDS[field] || null;
}

module.exports = { ECS_FIELDS, isKnownEcsField, getEcsFieldInfo };
