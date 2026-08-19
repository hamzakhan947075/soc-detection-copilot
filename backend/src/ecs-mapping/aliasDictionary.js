'use strict';

/**
 * Field-name alias dictionary. Keys are normalized (lowercase, separators
 * stripped) raw field names commonly seen in non-ECS logs (Elastic exports,
 * CSV exports, syslog-derived JSON, etc). Each candidate carries the ECS
 * field it maps to, the expected primitive value type (used to validate the
 * guess against actual sample values), a base confidence, and a short reason.
 *
 * This is deterministic, data-driven mapping - no AI involved - which is why
 * it lives as a plain lookup table rather than inferred logic.
 */
const ALIASES = {
  // timestamps
  timestamp: [{ ecs: '@timestamp', type: 'date', confidence: 0.97, reason: 'Field name indicates event time' }],
  time: [{ ecs: '@timestamp', type: 'date', confidence: 0.85, reason: 'Generic time field, likely the event timestamp' }],
  datetime: [{ ecs: '@timestamp', type: 'date', confidence: 0.9, reason: 'Field name indicates event date/time' }],
  eventtime: [{ ecs: '@timestamp', type: 'date', confidence: 0.92, reason: 'Explicit event time field' }],

  // messages
  msg: [{ ecs: 'message', type: 'string', confidence: 0.9, reason: 'Common abbreviation for the log message' }],
  logmessage: [{ ecs: 'message', type: 'string', confidence: 0.88, reason: 'Field name indicates the raw log message' }],

  // network / IP
  srcip: [{ ecs: 'source.ip', type: 'ip', confidence: 0.98, reason: 'Field name and IPv4/IPv6 values indicate a source address' }],
  src_ip: [{ ecs: 'source.ip', type: 'ip', confidence: 0.98, reason: 'Field name and IPv4/IPv6 values indicate a source address' }],
  sourceip: [{ ecs: 'source.ip', type: 'ip', confidence: 0.98, reason: 'Field name explicitly indicates a source IP' }],
  clientip: [{ ecs: 'client.ip', type: 'ip', confidence: 0.93, reason: 'Field name indicates a client IP address' }],
  remoteaddr: [{ ecs: 'client.ip', type: 'ip', confidence: 0.85, reason: 'Common web-server field for the remote client address' }],
  remoteip: [{ ecs: 'source.ip', type: 'ip', confidence: 0.85, reason: 'Generic remote-address field, most often the connection source' }],
  dstip: [{ ecs: 'destination.ip', type: 'ip', confidence: 0.98, reason: 'Field name and IP values indicate a destination address' }],
  dst_ip: [{ ecs: 'destination.ip', type: 'ip', confidence: 0.98, reason: 'Field name and IP values indicate a destination address' }],
  destip: [{ ecs: 'destination.ip', type: 'ip', confidence: 0.97, reason: 'Field name explicitly indicates a destination IP' }],
  destinationip: [{ ecs: 'destination.ip', type: 'ip', confidence: 0.98, reason: 'Field name explicitly indicates a destination IP' }],
  serverip: [{ ecs: 'server.ip', type: 'ip', confidence: 0.9, reason: 'Field name indicates the serving host IP' }],
  hostip: [{ ecs: 'host.ip', type: 'ip', confidence: 0.9, reason: 'Field name indicates the originating host IP' }],
  ip: [{ ecs: 'source.ip', type: 'ip', confidence: 0.55, reason: 'Generic IP field with no source/destination qualifier' },
    { ecs: 'destination.ip', type: 'ip', confidence: 0.45, reason: 'Could also represent a destination address' }],

  srcport: [{ ecs: 'source.port', type: 'port', confidence: 0.95, reason: 'Field name indicates a source port' }],
  src_port: [{ ecs: 'source.port', type: 'port', confidence: 0.95, reason: 'Field name indicates a source port' }],
  dstport: [{ ecs: 'destination.port', type: 'port', confidence: 0.95, reason: 'Field name indicates a destination port' }],
  dst_port: [{ ecs: 'destination.port', type: 'port', confidence: 0.95, reason: 'Field name indicates a destination port' }],
  port: [{ ecs: 'destination.port', type: 'port', confidence: 0.5, reason: 'Generic port field, direction unclear' }],

  protocol: [{ ecs: 'network.protocol', type: 'string', confidence: 0.85, reason: 'Field name indicates an application protocol' }],
  proto: [{ ecs: 'network.transport', type: 'string', confidence: 0.75, reason: 'Common abbreviation for the transport protocol' }],

  // hosts
  hostname: [{ ecs: 'host.name', type: 'hostname', confidence: 0.95, reason: 'Field name explicitly indicates a hostname' }],
  host: [{ ecs: 'host.name', type: 'string', confidence: 0.8, reason: 'Generic host field, most often the host name' }],
  computername: [{ ecs: 'host.name', type: 'string', confidence: 0.93, reason: 'Windows-style field name for the host name' }],
  devicename: [{ ecs: 'host.name', type: 'string', confidence: 0.8, reason: 'Field name indicates a device/host identifier' }],

  // users
  username: [{ ecs: 'user.name', type: 'string', confidence: 0.97, reason: 'Field name explicitly indicates an account name' }],
  user: [{ ecs: 'user.name', type: 'string', confidence: 0.85, reason: 'Generic user field, most often the account name' }],
  account: [{ ecs: 'user.name', type: 'string', confidence: 0.75, reason: 'Field name suggests an account identifier' }],
  accountname: [{ ecs: 'user.name', type: 'string', confidence: 0.9, reason: 'Windows-style field name for the account name' }],
  targetusername: [{ ecs: 'user.target.name', type: 'string', confidence: 0.9, reason: 'Windows security log field for the target account of the event' }],
  userid: [{ ecs: 'user.id', type: 'string', confidence: 0.85, reason: 'Field name indicates a unique user identifier' }],

  // actions / outcomes
  action: [{ ecs: 'event.action', type: 'string', confidence: 0.9, reason: 'Field name indicates the action performed' }],
  eventaction: [{ ecs: 'event.action', type: 'string', confidence: 0.95, reason: 'Field name explicitly indicates the event action' }],
  status: [{ ecs: 'event.outcome', type: 'string', confidence: 0.8, reason: 'Field name suggests success/failure outcome' }],
  result: [{ ecs: 'event.outcome', type: 'string', confidence: 0.78, reason: 'Field name suggests success/failure outcome' }],
  outcome: [{ ecs: 'event.outcome', type: 'string', confidence: 0.92, reason: 'Field name explicitly indicates event outcome' }],
  disposition: [{ ecs: 'event.outcome', type: 'string', confidence: 0.7, reason: 'Firewall-style field indicating allow/deny outcome' }],

  // process
  processname: [{ ecs: 'process.name', type: 'string', confidence: 0.93, reason: 'Field name explicitly indicates a process name' }],
  process: [{ ecs: 'process.name', type: 'string', confidence: 0.75, reason: 'Generic process field, most often the process name' }],
  commandline: [{ ecs: 'process.command_line', type: 'string', confidence: 0.93, reason: 'Field name explicitly indicates a command line' }],
  cmdline: [{ ecs: 'process.command_line', type: 'string', confidence: 0.9, reason: 'Abbreviated form of command line field' }],
  pid: [{ ecs: 'process.pid', type: 'number', confidence: 0.9, reason: 'Field name explicitly indicates a process ID' }],
  parentprocessname: [{ ecs: 'process.parent.name', type: 'string', confidence: 0.9, reason: 'Field name indicates the parent process name' }],

  // files
  filepath: [{ ecs: 'file.path', type: 'string', confidence: 0.92, reason: 'Field name explicitly indicates a file path' }],
  filename: [{ ecs: 'file.name', type: 'string', confidence: 0.92, reason: 'Field name explicitly indicates a file name' }],
  sha256: [{ ecs: 'file.hash.sha256', type: 'string', confidence: 0.9, reason: 'Field name indicates a SHA-256 hash value' }],

  // web / http
  url: [{ ecs: 'url.original', type: 'string', confidence: 0.85, reason: 'Field name indicates a full URL' }],
  uri: [{ ecs: 'url.original', type: 'string', confidence: 0.8, reason: 'Field name indicates a full URI' }],
  requesturl: [{ ecs: 'url.original', type: 'string', confidence: 0.88, reason: 'Field name explicitly indicates the request URL' }],
  requestmethod: [{ ecs: 'http.request.method', type: 'string', confidence: 0.9, reason: 'Field name indicates the HTTP method' }],
  method: [{ ecs: 'http.request.method', type: 'string', confidence: 0.7, reason: 'Generic method field, likely the HTTP verb' }],
  statuscode: [{ ecs: 'http.response.status_code', type: 'number', confidence: 0.9, reason: 'Field name indicates an HTTP status code' }],
  useragent: [{ ecs: 'user_agent.original', type: 'string', confidence: 0.9, reason: 'Field name explicitly indicates a user agent string' }],
  referrer: [{ ecs: 'http.request.referrer', type: 'string', confidence: 0.85, reason: 'Field name indicates the HTTP referrer' }],

  // dns
  dnsquery: [{ ecs: 'dns.question.name', type: 'string', confidence: 0.9, reason: 'Field name indicates a DNS query name' }],
  query: [{ ecs: 'dns.question.name', type: 'string', confidence: 0.55, reason: 'Generic query field, possibly a DNS question name' }],
  querytype: [{ ecs: 'dns.question.type', type: 'string', confidence: 0.85, reason: 'Field name indicates a DNS record type' }],

  // dataset / rule
  dataset: [{ ecs: 'event.dataset', type: 'string', confidence: 0.85, reason: 'Field name indicates the log dataset' }],
  rulename: [{ ecs: 'rule.name', type: 'string', confidence: 0.88, reason: 'Field name explicitly indicates a rule/signature name' }],
  signature: [{ ecs: 'rule.name', type: 'string', confidence: 0.8, reason: 'Field name suggests an IDS/IPS rule signature' }],

  // cloud
  provider: [{ ecs: 'cloud.provider', type: 'string', confidence: 0.6, reason: 'Generic provider field, possibly the cloud provider' }],
  region: [{ ecs: 'cloud.region', type: 'string', confidence: 0.6, reason: 'Generic region field, possibly the cloud region' }],
  accountid: [{ ecs: 'cloud.account.id', type: 'string', confidence: 0.65, reason: 'Field name suggests a cloud account identifier' }],

  // bytes / severity
  bytes: [{ ecs: 'network.bytes', type: 'number', confidence: 0.7, reason: 'Field name indicates transferred byte count' }],
  severity: [{ ecs: 'event.severity', type: 'number', confidence: 0.75, reason: 'Field name indicates an event severity value' }],
  loglevel: [{ ecs: 'log.level', type: 'string', confidence: 0.85, reason: 'Field name explicitly indicates a log level' }],
};

function normalizeFieldName(name) {
  return String(name)
    .toLowerCase()
    .replace(/\[\d+\]/g, '')
    .replace(/[^a-z0-9]/g, '');
}

module.exports = { ALIASES, normalizeFieldName };
