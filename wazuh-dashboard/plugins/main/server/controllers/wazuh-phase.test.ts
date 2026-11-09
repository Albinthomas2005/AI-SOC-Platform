import { WazuhPhaseCtrl } from './wazuh-phase';

/* eslint-disable @typescript-eslint/no-explicit-any */
jest.mock('needle', () => jest.fn());

// Needle has no TypeScript declaration in this plugin.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const needle = require('needle') as jest.Mock;
const controller = new WazuhPhaseCtrl();
const originalInternalToken = process.env.SOC_AI_INTERNAL_TOKEN;

const createContext = () => ({
  wazuh: { security: { getCurrentUser: jest.fn().mockResolvedValue({ username: 'analyst' }) } },
} as any);

const createResponse = () => ({
  ok: jest.fn(value => ({ statusCode: 200, ...value })),
  custom: jest.fn(value => value),
});

describe('Wazuh phase proxy backend errors', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SOC_AI_INTERNAL_TOKEN = 'synthetic-internal-token';
  });

  afterAll(() => {
    if (originalInternalToken === undefined) {
      delete process.env.SOC_AI_INTERNAL_TOKEN;
    } else {
      process.env.SOC_AI_INTERNAL_TOKEN = originalInternalToken;
    }
  });

  it.each([
    [400, 'Invalid request'],
    [401, 'Authentication failed'],
    [500, 'Internal backend failure'],
  ])('returns backend status %i and its error message', async (statusCode, message) => {
    needle.mockResolvedValue({ statusCode, body: { ok: false, error: message } });
    const response = createResponse();

    const result = await controller.proxy(
      createContext(), {} as any, response as any, 'get', '/api/status',
    );

    expect(result).toEqual({ statusCode, body: { ok: false, error: message } });
  });

  it('redacts the internal token from a backend error message', async () => {
    needle.mockResolvedValue({
      statusCode: 500,
      body: { ok: false, error: 'Request failed with synthetic-internal-token' },
    });
    const response = createResponse();

    const result = await controller.proxy(
      createContext(), {} as any, response as any, 'get', '/api/status',
    );

    expect(result.body.error).toBe('Request failed with [redacted]');
    expect(result.body.error).not.toContain('synthetic-internal-token');
  });

  it('returns a clear message when the backend connection fails', async () => {
    needle.mockRejectedValue(new Error('connect ECONNREFUSED'));
    const response = createResponse();

    const result = await controller.proxy(
      createContext(), {} as any, response as any, 'get', '/api/status',
    );

    expect(result).toEqual({ statusCode: 503, body: { ok: false, error: 'backend unreachable' } });
  });
});
