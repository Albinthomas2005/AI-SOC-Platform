import { WazuhAiCtrl } from '../controllers/wazuh-ai';

/* eslint-disable @typescript-eslint/no-explicit-any */
jest.mock('needle', () => jest.fn());
// eslint-disable-next-line @typescript-eslint/no-var-requires
const needle = require('needle') as jest.Mock;
const controller = new WazuhAiCtrl();
const index = 'wazuh-alerts-4.x-2026.10.28';
const id = 'synthetic-alert-id';
const source = {
  timestamp: '2026-10-28T10:00:00.000Z',
  rule: {
    id: '1001',
    level: 8,
    description: 'Synthetic alert',
    groups: ['authentication_failed'],
  },
  agent: { id: '007', name: 'synthetic-host', ip: '192.0.2.20' },
  data: { srcip: '198.51.100.42', password: 'synthetic-secret' },
  full_log: 'synthetic raw log',
};
const createContext = () => {
  const search = jest
    .fn()
    .mockResolvedValue({ body: { hits: { hits: [{ _source: source }] } } });
  return {
    wazuh: {
      security: {
        getCurrentUser: jest.fn().mockResolvedValue({ username: 'analyst' }),
      },
    },
    wazuh_core: {
      configuration: {
        getSettingValue: jest.fn().mockResolvedValue('wazuh-alerts-*'),
      },
    },
    core: { opensearch: { client: { asCurrentUser: { search } } } },
    search,
  } as any;
};
const createResponse = () => ({
  ok: jest.fn(value => ({ statusCode: 200, ...value })),
  custom: jest.fn(value => value),
});
const createRequest = (body = {}) => ({ body: { index, id, ...body } } as any);
const originalToken = process.env.SOC_AI_INTERNAL_TOKEN;

describe('POST /api/ai/generate-report controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SOC_AI_INTERNAL_TOKEN = 'synthetic-internal-token';
    needle.mockResolvedValue({
      statusCode: 200,
      body: {
        ok: true,
        analysis_id: '0123456789abcdef0123456789abcdef',
        status: 'ai_generated_unverified',
        decision: 'unreviewed',
        decision_label: 'AI draft - not reviewed',
        decided_at: null,
        evidence: {
          index,
          id,
          alert: {
            timestamp: source.timestamp,
            rule: source.rule,
            agent: { id: '007' },
            data: { srcip: '198.51.100.42' },
          },
        },
        report: 'Synthetic report draft',
      },
    });
  });
  afterAll(() => {
    if (originalToken === undefined) delete process.env.SOC_AI_INTERNAL_TOKEN;
    else process.env.SOC_AI_INTERNAL_TOKEN = originalToken;
  });

  it('re-reads the alert as the signed-in user and forwards only allowlisted evidence', async () => {
    const context = createContext();
    const response = createResponse();
    const result = await controller.generateReport(
      context,
      createRequest({ analyst_notes: 'Synthetic analyst note' }),
      response as any,
    );
    expect(result.body).toEqual(
      expect.objectContaining({
        ok: true,
        status: 'ai_generated_unverified',
        report: 'Synthetic report draft',
      }),
    );
    expect(context.search).toHaveBeenCalledTimes(1);
    const forwarded = needle.mock.calls[0][2];
    expect(forwarded.evidence).toEqual(
      expect.objectContaining({
        index,
        id,
        alert: expect.objectContaining({
          timestamp: source.timestamp,
          rule: source.rule,
        }),
      }),
    );
    expect(JSON.stringify(forwarded)).not.toContain('full_log');
    expect(JSON.stringify(forwarded)).not.toContain('synthetic-secret');
    expect(needle.mock.calls[0][1]).toBe(
      'http://127.0.0.1:5000/api/ai/generate-report',
    );
  });

  it('rejects unauthenticated users without searching or calling the service', async () => {
    const context = createContext();
    context.wazuh.security.getCurrentUser.mockResolvedValue(null);
    const result = await controller.generateReport(
      context,
      createRequest(),
      createResponse() as any,
    );
    expect(result.statusCode).toBe(401);
    expect(context.search).not.toHaveBeenCalled();
    expect(needle).not.toHaveBeenCalled();
  });

  it('enforces the analyst note limit and does not call the provider', async () => {
    const result = await controller.generateReport(
      createContext(),
      createRequest({ analyst_notes: 'x'.repeat(4001) }),
      createResponse() as any,
    );
    expect(result.statusCode).toBe(400);
    expect(needle).not.toHaveBeenCalled();
  });

  it('does not pass alerts forbidden by the current user to the provider', async () => {
    const context = createContext();
    context.search.mockRejectedValue({ meta: { statusCode: 403 } });
    const result = await controller.generateReport(
      context,
      createRequest(),
      createResponse() as any,
    );
    expect(result.statusCode).toBe(403);
    expect(needle).not.toHaveBeenCalled();
  });

  it('forwards analyst decisions to the protected backend endpoint', async () => {
    needle.mockResolvedValueOnce({
      statusCode: 200,
      body: {
        ok: true,
        analysis_id: '0123456789abcdef0123456789abcdef',
        decision: 'approved',
        decision_label: 'Analyst approved',
        decided_at: '2026-11-07T10:00:00Z',
        note: 'Reviewed synthetic evidence',
      },
    });
    const result = await controller.recordAnalysisDecision(
      createContext(),
      {
        body: {
          analysis_id: '0123456789abcdef0123456789abcdef',
          decision: 'approved',
          note: 'Reviewed synthetic evidence',
        },
      } as any,
      createResponse() as any,
    );

    expect(result.body).toEqual(
      expect.objectContaining({ ok: true, decision: 'approved' }),
    );
    expect(needle.mock.calls[0][1]).toBe(
      'http://127.0.0.1:5000/api/ai/analysis/0123456789abcdef0123456789abcdef/decision',
    );
    expect(needle.mock.calls[0][2]).toEqual({
      decision: 'approved',
      note: 'Reviewed synthetic evidence',
      edited_analysis: undefined,
    });
  });
});
