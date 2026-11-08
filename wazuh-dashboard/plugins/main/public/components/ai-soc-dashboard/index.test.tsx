import '@testing-library/jest-dom';
import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Switch } from 'react-router-dom';
import NavigationService from '../../react-services/navigation-service';
import { WzRequest } from '../../react-services/wz-request';
import { AiSocDashboard } from './index';
import { aiSocDashboardRoute } from './route';
import { useAiSocOverview } from './use-ai-soc-overview';
import { Applications } from '../../utils/applications';

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
  it('mounts the dashboard through its production Route component binding', () => {
    render(
      <MemoryRouter initialEntries={['/ai-soc-dashboard']}>
        <Switch>{aiSocDashboardRoute}</Switch>
      </MemoryRouter>,
    );
    expect(screen.getByRole('heading', { name: 'AI SOC Dashboard' })).toBeInTheDocument();
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
  it('opens the registered SOC Workbench from the dashboard', () => {
    const navigateToApp = jest.fn();
    (NavigationService.getInstance as jest.Mock).mockReturnValue({ navigateToApp });
    render(<AiSocDashboard />);
    fireEvent.click(screen.getByRole('button', { name: 'Workbench' }));
    expect(navigateToApp).toHaveBeenCalledWith('security-operations-workbench');
  });
  it('keeps the SOC Workbench registered in the left navigation application list', () => {
    expect(Applications.some(application => application.id === 'security-operations-workbench')).toBe(true);
  });
  it('requests a report by alert reference and marks the response unverified', async () => {
    (WzRequest.genericReq as jest.Mock).mockResolvedValue({
      data: {
        ok: true,
        analysis_id: '0123456789abcdef0123456789abcdef',
        status: 'ai_generated_unverified',
        decision: 'unreviewed',
        decision_label: 'AI draft - not reviewed',
        report: '## Assessment\n\nSynthetic report draft\n<img src=x onerror=alert(1)>',
      },
    });
    const { container } = render(<AiSocDashboard />);
    fireEvent.click(screen.getByRole('button', { name: 'Generate report' }));
    expect(
      await screen.findByText((_, element) =>
        element?.tagName === 'PRE' &&
        element.textContent === '## Assessment\n\nSynthetic report draft\n<img src=x onerror=alert(1)>',
      ),
    ).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    expect(
      screen.getByText('AI draft - not reviewed'),
    ).toBeInTheDocument();
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST',
      '/api/ai/generate-report',
      { index: data.recentAlerts[0].index, id: data.recentAlerts[0].id },
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
  });
  it('saves an analyst approval for the generated report', async () => {
    (WzRequest.genericReq as jest.Mock)
      .mockResolvedValueOnce({
        data: {
          ok: true,
          analysis_id: '0123456789abcdef0123456789abcdef',
          status: 'ai_generated_unverified',
          decision: 'unreviewed',
          decision_label: 'AI draft - not reviewed',
          report: 'Synthetic draft',
        },
      })
      .mockResolvedValueOnce({
        data: {
          ok: true,
          analysis_id: '0123456789abcdef0123456789abcdef',
          decision: 'approved',
          decided_at: '2026-11-07T10:00:00Z',
        },
      });
    render(<AiSocDashboard />);
    fireEvent.click(screen.getByRole('button', { name: 'Generate report' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));

    expect(await screen.findByText('Analyst decision: approved')).toBeInTheDocument();
    expect(WzRequest.genericReq).toHaveBeenLastCalledWith(
      'POST',
      '/api/ai/analysis/decision',
      {
        analysis_id: '0123456789abcdef0123456789abcdef',
        decision: 'approved',
        note: '',
      },
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
