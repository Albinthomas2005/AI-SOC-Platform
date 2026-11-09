import '@testing-library/jest-dom';
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { WzRequest } from '../../react-services/wz-request';
import { PhaseWorkbench } from './index';

jest.mock('../../react-services/wz-request', () => ({ WzRequest: { genericReq: jest.fn() } }));

describe('PhaseWorkbench', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (WzRequest.genericReq as jest.Mock).mockResolvedValue({ data: { ok: true, groups: [], incidents: [], events: [] } });
  });

  it('exposes the phase screens and calls the authenticated plugin correlation route', async () => {
    render(<PhaseWorkbench />);
    fireEvent.click(screen.getByRole('button', { name: 'Build correlation timeline' }));
    await waitFor(() => expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST', '/api/phase/correlations/run',
      { alert_refs: [{ index: 'wazuh-alerts-4.x-2026.11.08', id: 'replace-with-alert-id' }] },
      { shouldRetry: false, checkCurrentApiIsUp: false },
    ));
    for (const label of ['Correlation', 'Incidents', 'Threat intel', 'Hunting', 'Audit', 'Assistant']) {
      expect(screen.getByRole('tab', { name: label })).toBeInTheDocument();
    }
  });

  it('shows loading and disables duplicate actions while a request is pending', async () => {
    let resolveRequest!: (value: unknown) => void;
    (WzRequest.genericReq as jest.Mock).mockReturnValue(
      new Promise(resolve => { resolveRequest = resolve; }),
    );
    render(<PhaseWorkbench />);
    fireEvent.click(screen.getByRole('button', { name: 'Build correlation timeline' }));
    expect(screen.getByRole('status')).toHaveTextContent('Loading');
    expect(screen.getByRole('button', { name: 'Build correlation timeline' })).toBeDisabled();
    resolveRequest({ data: { ok: true, groups: [] } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Build correlation timeline' })).toBeEnabled());
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('shows an empty state when the backend returns no findings', async () => {
    render(<PhaseWorkbench />);
    fireEvent.click(screen.getByRole('button', { name: 'Build correlation timeline' }));
    expect(await screen.findByText('No results were returned.')).toBeInTheDocument();
  });

  it.each([
    ['Correlation', 'Build correlation timeline'],
    ['Incidents', 'Refresh incidents'],
    ['Threat intel', 'Look up threat indicators'],
    ['Hunting', 'Run hunt'],
    ['Audit', 'Load audit events'],
    ['Assistant', 'Ask assistant'],
  ])('shows an empty state in the %s panel', async (panel, action) => {
    render(<PhaseWorkbench />);
    fireEvent.click(screen.getByRole('tab', { name: panel }));
    fireEvent.click(screen.getByRole('button', { name: action }));
    expect(await screen.findByText('No results were returned.')).toBeInTheDocument();
  });

  it.each([
    ['Correlation', 'Build correlation timeline'],
    ['Incidents', 'Refresh incidents'],
    ['Threat intel', 'Look up threat indicators'],
    ['Hunting', 'Run hunt'],
    ['Audit', 'Load audit events'],
    ['Assistant', 'Ask assistant'],
  ])('shows loading and error states in the %s panel', async (panel, action) => {
    let rejectRequest!: (reason: Error) => void;
    (WzRequest.genericReq as jest.Mock).mockReturnValue(
      new Promise((_, reject) => { rejectRequest = reject; }),
    );
    render(<PhaseWorkbench />);
    fireEvent.click(screen.getByRole('tab', { name: panel }));
    fireEvent.click(screen.getByRole('button', { name: action }));
    expect(screen.getByRole('status')).toHaveTextContent('Loading');
    rejectRequest(new Error('Synthetic unavailable'));
    expect(await screen.findByText('Synthetic unavailable')).toBeInTheDocument();
    expect(screen.queryByRole('status')).toBeNull();
  });
});
