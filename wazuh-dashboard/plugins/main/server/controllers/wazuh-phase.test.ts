import { WazuhPhaseCtrl } from './wazuh-phase';

/* eslint-disable @typescript-eslint/no-explicit-any */
jest.mock('needle', () => jest.fn());

// Needle has no TypeScript declaration in this plugin.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const needle = require('needle') as jest.Mock;
const controller = new WazuhPhaseCtrl();
const originalInternalToken = process.env.SOC_AI_INTERNAL_TOKEN;
const originalBaseUrl = process.env.SOC_AI_BASE_URL;
const originalHost = process.env.SOC_AI_HOST;
const originalPort = process.env.SOC_AI_PORT;

const createContext = () => ({
  wazuh: {
    security: { getCurrentUser: jest.fn().mockResolvedValue({ username: 'analyst' }) },
    logger: { error: jest.fn() },
  },
} as any);

const createResponse = () => ({
  ok: jest.fn(value => ({ statusCode: 200, ...value })),
  custom: jest.fn(value => value),
});

describe('Wazuh phase proxy backend errors', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SOC_AI_INTERNAL_TOKEN = 'synthetic-internal-token';
    process.env.SOC_AI_BASE_URL = 'http://127.0.0.1:5000';
  });

  afterAll(() => {
    if (originalInternalToken === undefined) {
      delete process.env.SOC_AI_INTERNAL_TOKEN;
    } else {
      process.env.SOC_AI_INTERNAL_TOKEN = originalInternalToken;
    }
    if (originalBaseUrl === undefined) delete process.env.SOC_AI_BASE_URL;
    else process.env.SOC_AI_BASE_URL = originalBaseUrl;
    if (originalHost === undefined) delete process.env.SOC_AI_HOST;
    else process.env.SOC_AI_HOST = originalHost;
    if (originalPort === undefined) delete process.env.SOC_AI_PORT;
    else process.env.SOC_AI_PORT = originalPort;
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

    expect(result).toEqual({ statusCode, body: { ok: false, error: message, message } });
  });

  it('supplies a fallback message when a non-2xx backend response has no body', async () => {
    needle.mockResolvedValue({ statusCode: 500, body: undefined });
    const response = createResponse();

    const result = await controller.proxy(
      createContext(), {} as any, response as any, 'post', '/api/lab/uploads',
      { filename: 'sample.log', content: 'synthetic', title: 'sample', platform: 'linux' },
    );

    expect(result).toEqual({
      statusCode: 500,
      body: { ok: false, error: 'Backend returned HTTP 500', message: 'Backend returned HTTP 500' },
    });
    expect(needle).toHaveBeenCalledWith(
      'post', expect.stringContaining('/api/lab/uploads'),
      { filename: 'sample.log', content: 'synthetic', title: 'sample', platform: 'linux' },
      expect.any(Object),
    );
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
    expect(result.body.message).toBe('Request failed with [redacted]');
    expect(JSON.stringify(result.body)).not.toContain('synthetic-internal-token');
  });

  it('returns a clear message when the backend connection fails', async () => {
    needle.mockRejectedValue(new Error('connect ECONNREFUSED'));
    const response = createResponse();

    const result = await controller.proxy(
      createContext(), {} as any, response as any, 'get', '/api/status',
    );

    expect(result).toEqual({ statusCode: 503, body: { ok: false, error: 'backend unreachable', message: 'backend unreachable' } });
  });

  it('returns the upload build header on a successful upload response', async () => {
    needle.mockResolvedValue({ statusCode: 201, body: { ok: true, upload: { id: 'synthetic-id' } } });
    const response = createResponse();

    const result = await controller.uploadLab(
      createContext(), { body: Buffer.from('{"filename":"sample.log","content":"sample","title":"Sample","platform":"linux"}') } as any,
      response as any,
    );

    expect(result.statusCode).toBe(201);
    expect(result.headers['x-soc-ai-build']).toBe('upload-diagnose-1');
    expect(result.body).toEqual({ ok: true, upload: { id: 'synthetic-id' } });
  });

  it('returns a message and build header for invalid upload JSON', async () => {
    const response = createResponse();
    const result = await controller.uploadLab(createContext(), { body: '{' } as any, response as any);

    expect(result.statusCode).toBe(400);
    expect(result.body.message).toBe('Upload request must contain valid JSON');
    expect(result.headers['x-soc-ai-build']).toBe('upload-diagnose-1');
    expect(needle).not.toHaveBeenCalled();
  });

  it('returns a message and build header when the raw upload body exceeds its limit', async () => {
    const response = createResponse();
    const result = await controller.uploadLab(
      createContext(), { body: Buffer.alloc(1024 * 1024 + 64 * 1024 + 1) } as any, response as any,
    );

    expect(result.statusCode).toBe(413);
    expect(result.body.message).toBe('Upload request exceeds the 1 MiB file limit');
    expect(result.headers['x-soc-ai-build']).toBe('upload-diagnose-1');
    expect(needle).not.toHaveBeenCalled();
  });

  it('reports missing backend token without exposing a token', async () => {
    delete process.env.SOC_AI_INTERNAL_TOKEN;
    const result = await controller.uploadLab(
      createContext(), { body: { filename: 'sample.log', content: 'synthetic', title: 'Sample', platform: 'linux' } } as any,
      createResponse() as any,
    );

    expect(result.statusCode).toBe(503);
    expect(result.body.message).toBe('backend token not configured');
    expect(result.headers['x-soc-ai-build']).toBe('upload-diagnose-1');
  });

  it('reports missing backend URL instead of using an import-time default', async () => {
    delete process.env.SOC_AI_BASE_URL;
    delete process.env.SOC_AI_HOST;
    delete process.env.SOC_AI_PORT;
    const result = await controller.uploadLab(
      createContext(), { body: { filename: 'sample.log', content: 'synthetic', title: 'Sample', platform: 'linux' } } as any,
      createResponse() as any,
    );

    expect(result.statusCode).toBe(503);
    expect(result.body.message).toBe('backend URL not configured');
    expect(result.headers['x-soc-ai-build']).toBe('upload-diagnose-1');
  });

  it('returns a non-empty response and safe log reason for a transport exception', async () => {
    needle.mockRejectedValue(new Error('token=synthetic-internal-token body=private upload content'));
    const context = createContext();
    const result = await controller.uploadLab(
      context, { body: { filename: 'sample.log', content: 'private upload content', title: 'Sample', platform: 'linux' } } as any,
      createResponse() as any,
    );

    expect(result.statusCode).toBe(503);
    expect(result.body.message).toBe('backend unreachable');
    expect(JSON.stringify(context.wazuh.logger.error.mock.calls)).not.toContain('synthetic-internal-token');
    expect(JSON.stringify(context.wazuh.logger.error.mock.calls)).not.toContain('private upload content');
  });
});
