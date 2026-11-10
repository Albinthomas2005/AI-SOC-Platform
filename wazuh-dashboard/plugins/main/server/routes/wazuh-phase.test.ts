import { WazuhPhaseRoutes } from './wazuh-phase';

/* eslint-disable @typescript-eslint/no-explicit-any */
jest.mock('needle', () => jest.fn());

// Needle has no TypeScript declaration.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const needle = require('needle') as jest.Mock;
const originalToken = process.env.SOC_AI_INTERNAL_TOKEN;
const originalBaseUrl = process.env.SOC_AI_BASE_URL;
const originalHost = process.env.SOC_AI_HOST;
const originalPort = process.env.SOC_AI_PORT;

describe('lab upload multipart route', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SOC_AI_INTERNAL_TOKEN = 'route-test-token';
    delete process.env.SOC_AI_BASE_URL;
    delete process.env.SOC_AI_HOST;
    delete process.env.SOC_AI_PORT;
  });

  afterAll(() => {
    if (originalToken === undefined) delete process.env.SOC_AI_INTERNAL_TOKEN;
    else process.env.SOC_AI_INTERNAL_TOKEN = originalToken;
    if (originalBaseUrl === undefined) delete process.env.SOC_AI_BASE_URL;
    else process.env.SOC_AI_BASE_URL = originalBaseUrl;
    if (originalHost === undefined) delete process.env.SOC_AI_HOST;
    else process.env.SOC_AI_HOST = originalHost;
    if (originalPort === undefined) delete process.env.SOC_AI_PORT;
    else process.env.SOC_AI_PORT = originalPort;
  });

  it('accepts a raw Buffer and forwards it with its multipart boundary', async () => {
    const handlers: Record<string, (context: any, request: any, response: any) => Promise<any>> = {};
    const router = {
      post: jest.fn((route: any, handler: any) => { handlers[route.path] = handler; }),
      get: jest.fn(),
      delete: jest.fn(),
    };
    WazuhPhaseRoutes(router as any);

    const route = router.post.mock.calls.find(([configuration]) => (
      (configuration as any).path === '/api/phase/lab/uploads'
    ))?.[0] as any;
    expect(route.options.body).toEqual({
      output: 'data',
      parse: false,
      accepts: 'multipart/form-data',
      maxBytes: 2 * 1024 * 1024,
    });

    const boundary = 'route-test-boundary';
    const multipart = Buffer.from([
      `--${boundary}`,
      'Content-Disposition: form-data; name="title"',
      '',
      'SSH upload test',
      `--${boundary}`,
      'Content-Disposition: form-data; name="platform"',
      '',
      'linux',
      `--${boundary}`,
      'Content-Disposition: form-data; name="file"; filename="linux_ssh_bruteforce.log"',
      'Content-Type: text/plain',
      '',
      'Nov  9 10:00:00 lab-linux sshd[10]: Failed password from 192.0.2.44',
      `--${boundary}--`,
      '',
    ].join('\r\n'));
    const context = {
      wazuh: {
        security: { getCurrentUser: jest.fn().mockResolvedValue({ username: 'analyst' }) },
        logger: { error: jest.fn() },
      },
    };
    const response = { custom: jest.fn(value => value) };
    needle.mockResolvedValue({ statusCode: 201, body: { ok: true, upload: { id: 'upload-1' } } });

    const result = await handlers['/api/phase/lab/uploads'](
      context,
      {
        body: multipart,
        headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
      },
      response,
    );

    expect(result.statusCode).toBe(201);
    expect(needle).toHaveBeenCalledWith(
      'post', 'http://127.0.0.1:5000/api/lab/uploads', multipart,
      expect.objectContaining({
        json: false,
        headers: expect.objectContaining({
          Authorization: 'Bearer route-test-token',
          'X-SOC-User': 'analyst',
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
        }),
      }),
    );
  });
});
