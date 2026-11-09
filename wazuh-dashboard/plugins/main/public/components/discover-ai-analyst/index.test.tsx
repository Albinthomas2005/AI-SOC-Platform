import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { WzRequest } from '../../react-services/wz-request';
import { DiscoverAIAnalyst } from './index';

jest.mock('../../react-services/wz-request', () => ({
  WzRequest: { genericReq: jest.fn() },
}));

const hit = {
  _id: 'alert-5501',
  _source: {
    rule: { id: '5501', description: 'sudo session', level: 3, groups: ['pam', 'syslog'] },
    agent: { name: 'host01' },
    data: { srcip: '198.51.100.9', srcuser: 'albin-thomas', dstuser: 'root' },
    location: '/var/log/auth.log',
    full_log: 'MUST NEVER BE SENT',
  },
};

const okResponse = {
  data: {
    ok: true,
    answer: 'The alert records a sudo session. [alert:alert-5501]\n<img src=x onerror=alert(1)>',
    citations: [{ type: 'alert', id: 'alert-5501' }],
  },
};

describe('DiscoverAIAnalyst', () => {
  beforeEach(() => jest.clearAllMocks());

  it('renders idle state', () => {
    render(<DiscoverAIAnalyst hit={hit} />);
    expect(screen.getByRole('button', { name: 'Analyze this alert' })).toBeInTheDocument();
  });

  it('renders loading state while the assistant request is pending', async () => {
    let resolveRequest!: (value: unknown) => void;
    (WzRequest.genericReq as jest.Mock).mockReturnValue(
      new Promise(resolve => { resolveRequest = resolve; }),
    );
    render(<DiscoverAIAnalyst hit={hit} />);
    fireEvent.click(screen.getByRole('button', { name: 'Analyze this alert' }));
    expect(screen.getByRole('status')).toHaveTextContent('Analyzing alert');
    expect(screen.getByRole('button', { name: 'Analyzing…' })).toBeDisabled();
    resolveRequest(okResponse);
    await screen.findByText(/records a sudo session/);
  });

  it('renders cited success as plain text and sends only allowlisted fields', async () => {
    (WzRequest.genericReq as jest.Mock).mockResolvedValue(okResponse);
    const { container } = render(<DiscoverAIAnalyst hit={hit} />);
    fireEvent.click(screen.getByRole('button', { name: 'Analyze this alert' }));
    expect(await screen.findByText(/records a sudo session/)).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('pre')).toHaveTextContent('<img src=x onerror=alert(1)>');
    const [, , requestBody] = (WzRequest.genericReq as jest.Mock).mock.calls[0];
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST',
      '/api/phase/assistant/chat',
      expect.any(Object),
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
    expect(requestBody.alert).toEqual({
      rule: { id: '5501', description: 'sudo session', level: 3, groups: ['pam', 'syslog'] },
      agent: { name: 'host01' },
      data: { srcip: '198.51.100.9', srcuser: 'albin-thomas', dstuser: 'root' },
      location: '/var/log/auth.log',
    });
    expect(JSON.stringify(requestBody)).not.toContain('full_log');
    expect(JSON.stringify(requestBody)).not.toContain('MUST NEVER BE SENT');
  });

  it('renders a safe error state', async () => {
    (WzRequest.genericReq as jest.Mock).mockRejectedValue(new Error('private details'));
    render(<DiscoverAIAnalyst hit={hit} />);
    fireEvent.click(screen.getByRole('button', { name: 'Analyze this alert' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The alert could not be analyzed');
    expect(screen.queryByText('private details')).toBeNull();
  });

  it('explains that the backend token is missing', async () => {
    (WzRequest.genericReq as jest.Mock).mockRejectedValue({ response: { status: 503 } });
    render(<DiscoverAIAnalyst hit={hit} />);
    fireEvent.click(screen.getByRole('button', { name: 'Analyze this alert' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('backend token is configured');
  });

  it('handles the supplied sudo alert without srcip and omits missing fields', async () => {
    const sudoHit = {
      _id: 'sudo-5501',
      _source: {
        rule: { id: '5501', level: 3, groups: ['pam', 'syslog', 'authentication_success'] },
        data: { srcuser: 'albin-thomas', dstuser: 'root' },
      },
    };
    const sudoResponse = {
      data: {
        ...okResponse.data,
        answer: 'The alert records a sudo session. [alert:sudo-5501]',
        citations: [{ type: 'alert', id: 'sudo-5501' }],
      },
    };
    (WzRequest.genericReq as jest.Mock).mockResolvedValue(sudoResponse);
    render(<DiscoverAIAnalyst hit={sudoHit} />);
    fireEvent.click(screen.getByRole('button', { name: 'Analyze this alert' }));
    await waitFor(() => expect(WzRequest.genericReq).toHaveBeenCalled());
    const [, , requestBody] = (WzRequest.genericReq as jest.Mock).mock.calls[0];
    expect(requestBody.alert).toEqual({
      rule: { id: '5501', level: 3, groups: ['pam', 'syslog', 'authentication_success'] },
      data: { srcuser: 'albin-thomas', dstuser: 'root' },
    });
    expect(requestBody.alert.data).not.toHaveProperty('srcip');
    expect(JSON.stringify(requestBody)).not.toContain('full_log');
  });
});
