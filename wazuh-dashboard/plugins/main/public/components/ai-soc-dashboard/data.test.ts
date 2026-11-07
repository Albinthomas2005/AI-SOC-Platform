import {
  buildAlertSeverityAgg,
  classifyAiSocQueryFailure,
  mapAiSocOverviewResponse,
} from './data';

const emptyResponse = {
  hits: { total: { value: 0, relation: 'eq' }, hits: [] },
  aggregations: {
    severity: {
      buckets: {
        critical: { doc_count: 0 },
        high: { doc_count: 0 },
        medium: { doc_count: 0 },
        low: { doc_count: 0 },
      },
    },
  },
};

describe('Wazuh 4 alert overview mapping', () => {
  it('maps Wazuh alert fields, numeric rule levels and OpenSearch hit metadata', () => {
    const response = {
      ...emptyResponse,
      hits: {
        total: { value: 1, relation: 'eq' },
        hits: [
          {
            _id: 'alert-1',
            _index: 'wazuh-alerts-4.x-2026.10.28',
            _source: {
              timestamp: '2026-10-28T10:00:00.000Z',
              rule: { description: 'Synthetic login failure', level: 13 },
              agent: { name: 'host-1' },
            },
          },
        ],
      },
      aggregations: {
        severity: {
          buckets: {
            critical: { doc_count: 0 },
            high: { doc_count: 1 },
            medium: { doc_count: 0 },
            low: { doc_count: 0 },
          },
        },
      },
    };
    expect(mapAiSocOverviewResponse(response)).toEqual({
      totalAlerts: 1,
      totalRelation: 'eq',
      severity: { critical: 0, high: 1, medium: 0, low: 0 },
      recentAlerts: [
        {
          id: 'alert-1',
          index: 'wazuh-alerts-4.x-2026.10.28',
          timestamp: '2026-10-28T10:00:00.000Z',
          title: 'Synthetic login failure',
          level: 13,
          severity: 'high',
          host: 'host-1',
        },
      ],
    });
  });

  it('preserves true empty results and lower-bound total semantics', () => {
    expect(mapAiSocOverviewResponse(emptyResponse).totalAlerts).toBe(0);
    expect(
      mapAiSocOverviewResponse({
        ...emptyResponse,
        hits: { total: { value: 10000, relation: 'gte' }, hits: [] },
      }).totalRelation,
    ).toBe('gte');
  });

  it('builds severity filters from Wazuh numeric rule levels', () => {
    expect(buildAlertSeverityAgg()).toEqual({
      severity: {
        filters: {
          filters: {
            critical: { range: { 'rule.level': { gte: 15, lte: 16 } } },
            high: { range: { 'rule.level': { gte: 12, lte: 14 } } },
            medium: { range: { 'rule.level': { gte: 7, lte: 11 } } },
            low: { range: { 'rule.level': { gte: 0, lte: 6 } } },
          },
        },
      },
    });
  });

  it('rejects incomplete search responses', () => {
    expect(() => mapAiSocOverviewResponse({ hits: { hits: [] } })).toThrow(
      'Invalid Wazuh alert search response',
    );
  });
});

describe('alert query failures', () => {
  it('classifies authentication and permission failures safely', () => {
    expect(classifyAiSocQueryFailure({ status: 401 }).kind).toBe(
      'unauthorized',
    );
    expect(classifyAiSocQueryFailure({ statusCode: 403 }).kind).toBe(
      'permission-denied',
    );
    expect(
      classifyAiSocQueryFailure('Alerts index pattern not found').kind,
    ).toBe('unavailable');
    expect(
      classifyAiSocQueryFailure({ statusCode: 503, message: 'private detail' })
        .message,
    ).not.toContain('private detail');
  });
});
