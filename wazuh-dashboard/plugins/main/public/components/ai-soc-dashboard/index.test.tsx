import '@testing-library/jest-dom';
import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import NavigationService from '../../react-services/navigation-service';
import { WzRequest } from '../../react-services/wz-request';
import { AiSocDashboard } from './index';
import { useAiSocOverview } from './use-ai-soc-overview';

jest.mock('../../react-services/navigation-service', () => ({
  __esModule: true,
  default: { getInstance: jest.fn() },
}));
jest.mock('../../react-services/wz-request', () => ({
  WzRequest: { genericReq: jest.fn() },
}));
jest.mock('./use-ai-soc-overview', () => ({ useAiSocOverview: jest.fn() }));

const data = {
  totalAlerts: 1,
  totalRelation: 'eq' as const,
  severity: { critical: 0, high: 1, medium: 0, low: 0 },
  recentAlerts: [
    {
      id: 'alert-1',
      index: 'wazuh-alerts-4.x-2026.10.28',
      timestamp: '2026-10-28T10:00:00.000Z',
      title: 'Synthetic alert',
      level: 13,
      severity: 'high' as const,
      host: 'host-1',
    },
  ],
};

describe('AiSocDashboard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (useAiSocOverview as jest.Mock).mockReturnValue({
      status: 'available',
      data,
    });
  });
  it('renders alert totals and evidence fields', () => {
    render(<AiSocDashboard />);
    expect(screen.getByText('Synthetic alert')).toBeInTheDocument();
    expect(screen.getByText('host-1')).toBeInTheDocument();
  });
  it('navigates into the existing Threat Hunting events view', () => {
    const navigateToApp = jest.fn();
    (NavigationService.getInstance as jest.Mock).mockReturnValue({
      navigateToApp,
    });
    render(<AiSocDashboard />);
    fireEvent.click(screen.getByRole('button', { name: 'Investigate alerts' }));
    expect(navigateToApp).toHaveBeenCalledWith('threat-hunting', {
      path: '#overview/?tab=general&tabView=events',
    });
  });
  it('requests a report by alert reference and marks the response unverified', async () => {
    (WzRequest.genericReq as jest.Mock).mockResolvedValue({
      data: {
        ok: true,
        status: 'ai_generated_unverified',
        report: 'Synthetic report draft',
      },
    });
    render(<AiSocDashboard />);
    fireEvent.click(screen.getByRole('button', { name: 'Generate report' }));
    expect(
      await screen.findByText('Synthetic report draft'),
    ).toBeInTheDocument();
    expect(
      screen.getByText('AI-generated report — unverified'),
    ).toBeInTheDocument();
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST',
      '/api/ai/generate-report',
      { index: data.recentAlerts[0].index, id: data.recentAlerts[0].id },
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
  });
  it('does not expose backend details when report generation fails', async () => {
    (WzRequest.genericReq as jest.Mock).mockRejectedValue(
      new Error('private backend detail'),
    );
    render(<AiSocDashboard />);
    fireEvent.click(screen.getByRole('button', { name: 'Generate report' }));
    expect(
      await screen.findByText(
        'Report generation is unavailable. Check the AI service and try again.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/private backend detail/)).toBeNull();
  });
});
