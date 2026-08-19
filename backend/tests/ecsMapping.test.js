'use strict';

const { suggestMapping } = require('../src/ecs-mapping/ecsMapper');
const { normalizeEvent } = require('../src/normalization/normalizer');
const { isKnownEcsField, isElasticsearchMetadataField, resolveTextMultifield, isKnownEcsNamespace } = require('../src/ecs-mapping/ecsSchema');
const { discoverFields } = require('../src/field-discovery/fieldDiscovery');

describe('suggestMapping', () => {
  test('maps a raw field already matching ECS with very high confidence', () => {
    const result = suggestMapping('source.ip', ['10.10.10.15']);
    expect(result.ecsField).toBe('source.ip');
    expect(result.confidence).toBeGreaterThan(0.95);
    expect(result.status).toBe('confident');
  });

  test('maps src_ip -> source.ip with high confidence when values look like IPs', () => {
    const result = suggestMapping('src_ip', ['10.10.10.15', '8.8.8.8']);
    expect(result.ecsField).toBe('source.ip');
    expect(result.confidence).toBeGreaterThanOrEqual(0.9);
  });

  test('maps username -> user.name', () => {
    const result = suggestMapping('username', ['admin', 'root']);
    expect(result.ecsField).toBe('user.name');
  });

  test('lowers confidence when observed values do not match the expected type', () => {
    const result = suggestMapping('src_ip', ['not-an-ip-address']);
    expect(result.confidence).toBeLessThan(0.6);
    expect(result.status).toBe('uncertain');
  });

  test('returns custom status for a field whose namespace is not part of ECS at all', () => {
    const result = suggestMapping('my_custom_widget_field', ['abc']);
    expect(result.status).toBe('custom');
    expect(result.ecsField).toBeNull();
  });

  test('returns unmapped (not custom) for a field under a real ECS namespace this app just does not carry a definition for', () => {
    const result = suggestMapping('host.totally_unrecognized_subfield', ['abc']);
    expect(result.status).toBe('unmapped');
    expect(result.ecsField).toBeNull();
  });

  test('returns unsupported when a name-based candidate exists but the observed values are arrays, not scalars', () => {
    const result = suggestMapping('username', [['admin', 'root']]);
    expect(result.status).toBe('unsupported');
    expect(result.ecsField).toBeNull();
  });

  test('never claims certainty for an ambiguous generic "ip" field', () => {
    const result = suggestMapping('ip', ['10.10.10.15']);
    expect(result.alternates.length).toBeGreaterThan(0);
  });
});

describe('ecsSchema', () => {
  test('recognizes canonical ECS fields', () => {
    expect(isKnownEcsField('source.ip')).toBe(true);
    expect(isKnownEcsField('totally.made.up')).toBe(false);
  });

  test('isKnownEcsNamespace recognizes a real ECS field group even when the specific sub-field is unrecognized', () => {
    expect(isKnownEcsNamespace('host.some_subfield_we_have_not_added')).toBe(true);
    expect(isKnownEcsNamespace('vulnerability.severity')).toBe(true); // a real ECS group with zero entries in ECS_FIELDS
    expect(isKnownEcsNamespace('@timestamp')).toBe(true);
  });

  test('isKnownEcsNamespace rejects a namespace that is not part of ECS at all', () => {
    expect(isKnownEcsNamespace('auth.mfa_used')).toBe(false);
    expect(isKnownEcsNamespace('patient.mfa_enforced')).toBe(false);
    expect(isKnownEcsNamespace('my_custom_widget_field')).toBe(false);
  });

  // Regression coverage for a real-world gap: a full Elastic export was
  // reported as ~90% "unmapped" even though almost every field was already
  // valid ECS - the schema dictionary just didn't cover it. These fields
  // come directly from that report.
  test('recognizes ECS fields beyond the original curated subset', () => {
    const realWorldEcsFields = [
      'agent.ephemeral_id',
      'agent.id',
      'agent.name',
      'data_stream.dataset',
      'data_stream.namespace',
      'data_stream.type',
      'ecs.version',
      'elastic_agent.id',
      'elastic_agent.snapshot',
      'elastic_agent.version',
      'event.created',
      'event.duration',
      'event.ingested',
      'event.kind',
      'event.reason',
      'event.risk_score',
      'host.architecture',
      'host.id',
      'host.mac',
      'host.os.family',
      'host.os.kernel',
      'host.os.platform',
      'host.os.type',
      'host.os.version',
      'http.request.bytes',
      'http.request.id',
      'http.request.mime_type',
      'http.response.bytes',
      'http.response.mime_type',
      'input.type',
      'log.logger',
      'network.type',
      'organization.id',
      'organization.name',
      'service.environment',
      'service.id',
      'source.as.number',
      'source.as.organization.name',
      'source.geo.city_name',
      'source.geo.continent_name',
      'source.geo.country_iso_code',
      'source.geo.location',
      'source.geo.region_iso_code',
      'source.geo.region_name',
      'tls.cipher',
      'tls.client.server_name',
      'tls.version',
      'url.extension',
      'url.full',
      'url.port',
      'url.scheme',
      'user_agent.device.name',
      'user_agent.name',
      'user_agent.os.name',
      'user_agent.version',
      'user.email',
    ];
    const stillMissing = realWorldEcsFields.filter((f) => !isKnownEcsField(f));
    expect(stillMissing).toEqual([]);
  });

  test('recognizes Elasticsearch hit metadata as excluded, not ECS', () => {
    expect(isElasticsearchMetadataField('_id')).toBe(true);
    expect(isElasticsearchMetadataField('_index')).toBe(true);
    expect(isElasticsearchMetadataField('_score')).toBe(true);
    expect(isElasticsearchMetadataField('_ignored')).toBe(true);
    expect(isElasticsearchMetadataField('event.id')).toBe(false);
  });

  test('resolves a .text multi-field to its known ECS base field', () => {
    expect(resolveTextMultifield('host.name.text')).toBe('host.name');
    expect(resolveTextMultifield('agent.name.text')).toBe('agent.name');
  });

  test('does not resolve .text for a base field that is not known ECS', () => {
    expect(resolveTextMultifield('totally.custom.text')).toBeNull();
  });
});

describe('suggestMapping - metadata and multi-field handling', () => {
  test('marks Elasticsearch metadata fields as excluded, not unmapped', () => {
    const result = suggestMapping('_id', ['abc123']);
    expect(result.status).toBe('excluded');
    expect(result.ecsField).toBeNull();
  });

  test('resolves a .text multi-field with high confidence', () => {
    const result = suggestMapping('host.name.text', ['server01']);
    expect(result.status).toBe('confident');
    expect(result.ecsField).toBe('host.name');
  });

  test('recognizes previously-missing ECS fields directly by name', () => {
    expect(suggestMapping('data_stream.dataset', ['logs']).status).toBe('confident');
    expect(suggestMapping('tls.version', ['TLSv1.3']).status).toBe('confident');
    expect(suggestMapping('user.email', ['a@example.com']).status).toBe('confident');
  });

  test('mappingMethod records how each kind of mapping was produced', () => {
    expect(suggestMapping('source.ip', ['10.10.10.15']).mappingMethod).toBe('exact');
    expect(suggestMapping('host.name.text', ['server01']).mappingMethod).toBe('text_multifield');
    expect(suggestMapping('username', ['admin']).mappingMethod).toBe('alias');
    expect(suggestMapping('_id', ['abc']).mappingMethod).toBeNull();
    expect(suggestMapping('auth.mfa_used', [true]).mappingMethod).toBeNull();
    expect(suggestMapping('host.unrecognized_subfield', ['x']).mappingMethod).toBeNull();
  });
});

describe('discoverFields - real-world Elastic export shape', () => {
  test('reports high coverage (not mass "unmapped") for a realistic already-ECS event', () => {
    const events = [
      {
        _id: 'abc',
        _index: 'logs-generic-default',
        _score: 1,
        '@timestamp': '2026-08-19T10:00:00Z',
        agent: { id: 'agent-1', name: 'filebeat', ephemeral_id: 'eph-1', type: 'filebeat', version: '8.14.0' },
        data_stream: { dataset: 'generic', namespace: 'default', type: 'logs' },
        ecs: { version: '8.11.0' },
        event: { category: ['authentication'], outcome: 'success', id: 'evt-1' },
        host: { name: 'server01', os: { family: 'debian', name: 'Ubuntu' } },
        source: { ip: '10.10.10.15', geo: { country_name: 'Norway' } },
        tls: { version: 'TLSv1.3' },
        user: { name: 'admin', email: 'admin@example.com' },
        // A genuinely custom, non-ECS application field - "auth" is not an
        // ECS field group, so this correctly reports "custom", not "unmapped".
        auth: { mfa_used: true },
      },
    ];
    const result = discoverFields(events);
    const byField = Object.fromEntries(result.fields.map((f) => [f.field, f]));

    expect(byField['_id'].ecsStatus).toBe('excluded');
    expect(byField['agent.id'].ecsStatus).toBe('confident');
    expect(byField['data_stream.dataset'].ecsStatus).toBe('confident');
    expect(byField['tls.version'].ecsStatus).toBe('confident');
    expect(byField['user.email'].ecsStatus).toBe('confident');
    expect(byField['auth.mfa_used'].ecsStatus).toBe('custom');

    const confidentCount = result.fields.filter((f) => f.ecsStatus === 'confident').length;
    expect(confidentCount).toBeGreaterThanOrEqual(10);
  });
});

describe('normalizeEvent', () => {
  test('builds a nested ECS object from flat mappings', () => {
    const raw = { src_ip: '10.10.10.15', username: 'admin', status: 'failure' };
    const mappings = [
      { rawField: 'src_ip', ecsField: 'source.ip', ecsType: 'ip' },
      { rawField: 'username', ecsField: 'user.name', ecsType: 'keyword' },
      { rawField: 'status', ecsField: 'event.outcome', ecsType: 'keyword' },
    ];
    const { normalized, changes } = normalizeEvent(raw, mappings);
    expect(normalized.source.ip).toBe('10.10.10.15');
    expect(normalized.user.name).toBe('admin');
    expect(normalized.event.outcome).toBe('failure');
    expect(changes).toHaveLength(3);
  });

  test('tracks unmapped fields without dropping data silently', () => {
    const raw = { weird_field: 'x' };
    const mappings = [{ rawField: 'weird_field', ecsField: null }];
    const { unmapped } = normalizeEvent(raw, mappings);
    expect(unmapped).toContain('weird_field');
  });

  test('coerces numeric string ports to numbers', () => {
    const raw = { dst_port: '443' };
    const mappings = [{ rawField: 'dst_port', ecsField: 'destination.port', ecsType: 'port' }];
    const { normalized } = normalizeEvent(raw, mappings);
    expect(normalized.destination.port).toBe(443);
  });
});
