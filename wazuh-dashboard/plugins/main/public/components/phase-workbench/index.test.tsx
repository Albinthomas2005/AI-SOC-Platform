import '@testing-library/jest-dom';
import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
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
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST', '/api/phase/correlations/run',
      { alert_refs: [{ index: 'wazuh-alerts-4.x-2026.11.08', id: 'replace-with-alert-id' }] },
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
    for (const label of ['Correlation', 'Incidents', 'Threat intel', 'Hunting', 'Audit', 'Assistant']) {
      expect(screen.getByRole('tab', { name: label })).toBeInTheDocument();
    }
  });
});
