import { WazuhHuntingCtrl } from '../controllers/wazuh-hunting';

/* eslint-disable @typescript-eslint/no-explicit-any, camelcase */
jest.mock('needle', () => jest.fn());
// Needle has no TypeScript declaration.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const needle = require('needle') as jest.Mock;
const controller = new WazuhHuntingCtrl();
const originalToken = process.env.SOC_AI_INTERNAL_TOKEN;
const query = {
  index: 'wazuh-alerts-4.x-*',
  size: 10,
  query: { bool: { must: [{ match: { 'rule.description': 'ssh authentication' } }] } },
};
const proposal = {
  hypothesis: 'Repeated failures precede a successful login.',
  query,
  mitre: [{ id: 'T1110', name: 'Brute Force' }],
};

const createContext = (username = 'analyst') => {
  const search = jest.fn().mockResolvedValue({
    body: { hits: { hits: [{ _id: 'alert-1', _source: { rule: { id: '5710' } } }] } },
  });
  return {
    wazuh: { security: { getCurrentUser: jest.fn().mockResolvedValue({ username }) } },
    core: { opensearch: { client: { asCurrentUser: { search } } } },
    search,
  } as any;
};

const createResponse = () => ({
  ok: jest.fn(value => ({ statusCode: 200, ...value })),
  custom: jest.fn(value => value),
});

describe('POST /api/hunts/run executes only validated proposals as current user', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SOC_AI_INTERNAL_TOKEN = 'synthetic-hunt-token';
    needle
      .mockResolvedValueOnce({ statusCode: 201, body: { ok: true, hunt_id: 'a'.repeat(32), proposal } })
      .mockResolvedValueOnce({ statusCode: 200, body: { ok: true, interpretation: 'Cites alert-1', result_count: 1 } });
  });

  afterAll(() => {
    if (originalToken === undefined) delete process.env.SOC_AI_INTERNAL_TOKEN;
    else process.env.SOC_AI_INTERNAL_TOKEN = originalToken;
  });

  it('proposes, searches as the signed-in user, and saves the resulting report', async () => {
    const context = createContext('signed-in-analyst');
    const response = createResponse();
    const result = await controller.runHunt(
      context,
      { body: { question: 'Find repeated SSH failures.' } } as any,
      response as any,
    );

    expect(result).toEqual({
      statusCode: 200,
      body: {
        ok: true,
        hunt_id: 'a'.repeat(32),
        proposal,
        interpretation: 'Cites alert-1',
        result_count: 1,
      },
    });
    expect(context.search).toHaveBeenCalledWith({
      index: 'wazuh-alerts-4.x-*',
      body: {
        size: 10,
        query: query.query,
        track_total_hits: false,
        _source: expect.arrayContaining(['@timestamp', 'rule.id', 'data.srcip']),
      },
    });
    expect(needle).toHaveBeenNthCalledWith(
      1,
      'post',
      expect.stringContaining('/api/hunts/proposals'),
      { question: 'Find repeated SSH failures.' },
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer synthetic-hunt-token',
          'X-SOC-User': 'signed-in-analyst',
        }),
      }),
    );
    expect(needle).toHaveBeenNthCalledWith(
      2,
      'post',
      expect.stringContaining(`/api/hunts/${'a'.repeat(32)}/results`),
      { results: [{ _id: 'alert-1', _source: { rule: { id: '5710' } } }] },
      expect.any(Object),
    );
  });

  it('does not query OpenSearch when no user is authenticated', async () => {
    const context = createContext();
    context.wazuh.security.getCurrentUser.mockResolvedValue(null);
    const response = createResponse();
    const result = await controller.runHunt(
      context,
      { body: { question: 'Find repeated SSH failures.' } } as any,
      response as any,
    );
    expect(result.statusCode).toBe(401);
    expect(context.search).not.toHaveBeenCalled();
    expect(needle).not.toHaveBeenCalled();
  });

  it('rejects a proposal with a non-allowlisted index before searching', async () => {
    needle.mockReset();
    needle.mockResolvedValueOnce({
      statusCode: 201,
      body: {
        ok: true,
        hunt_id: 'a'.repeat(32),
        proposal: { ...proposal, query: { ...query, index: '_all' } },
      },
    });
    const context = createContext();
    const response = createResponse();
    const result = await controller.runHunt(
      context,
      { body: { question: 'Find repeated SSH failures.' } } as any,
      response as any,
    );
    expect(result.statusCode).toBe(502);
    expect(context.search).not.toHaveBeenCalled();
  });
});
