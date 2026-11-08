import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { WzRequest } from '../../../../react-services/wz-request';
import { AIAnalysisTab } from './ai-analysis-tab';

jest.mock('../../../../react-services/wz-request', () => ({
  WzRequest: { genericReq: jest.fn() },
}));

const alertReference = { index: 'wazuh-alerts-4.x-2026.10.24', id: 'test-id' };
const analysisId = '0123456789abcdef0123456789abcdef';
const reportResponse = {
  data: {
    ok: true,
    status: 'ai_generated_unverified',
    analysis_id: analysisId,
    decision: 'unreviewed',
    report: '# Synthetic report\n\nReview this finding.',
  },
};

describe('AIAnalysisTab', () => {
  beforeEach(() => jest.clearAllMocks());

  it('generates a report for the selected alert and exposes its review state', async () => {
    (WzRequest.genericReq as jest.Mock).mockResolvedValue(reportResponse);
    render(<AIAnalysisTab {...alertReference} />);

    fireEvent.click(screen.getByRole('button', { name: 'Generate AI report' }));

    expect(await screen.findByText('AI draft - not reviewed')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Synthetic report' })).toBeInTheDocument();
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST',
      '/api/ai/generate-report',
      alertReference,
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
  });

  it('saves an edited report through the authenticated decision route', async () => {
    (WzRequest.genericReq as jest.Mock)
      .mockResolvedValueOnce(reportResponse)
      .mockResolvedValueOnce({ data: { ok: true, analysis_id: analysisId, decision: 'edited', edited_analysis: 'Analyst-edited report', decided_at: '2026-11-08T00:00:00Z' } });
    render(<AIAnalysisTab {...alertReference} />);
    fireEvent.click(screen.getByRole('button', { name: 'Generate AI report' }));
    await screen.findByText('AI draft - not reviewed');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Edit AI report' }), { target: { value: 'Analyst-edited report' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save edited report' }));

    expect(await screen.findByText('Analyst-edited report')).toBeInTheDocument();
    expect(WzRequest.genericReq).toHaveBeenLastCalledWith(
      'POST',
      '/api/ai/analysis/decision',
      { analysis_id: analysisId, decision: 'edited', note: '', edited_analysis: 'Analyst-edited report' },
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
  });

  it.each(['approved', 'rejected'] as const)(
    'records the %s decision for the generated report',
    async decision => {
      (WzRequest.genericReq as jest.Mock)
        .mockResolvedValueOnce(reportResponse)
        .mockResolvedValueOnce({ data: { ok: true, analysis_id: analysisId, decision, decided_at: '2026-11-08T00:00:00Z' } });
      render(<AIAnalysisTab {...alertReference} />);
      fireEvent.click(screen.getByRole('button', { name: 'Generate AI report' }));
      await screen.findByText('AI draft - not reviewed');
      fireEvent.click(screen.getByRole('button', { name: decision === 'approved' ? 'Approve' : 'Reject' }));

      await waitFor(() => expect(screen.getByText(`Analyst decision: ${decision}`)).toBeInTheDocument());
      expect(WzRequest.genericReq).toHaveBeenLastCalledWith(
        'POST',
        '/api/ai/analysis/decision',
        { analysis_id: analysisId, decision, note: '' },
        { shouldRetry: false, checkCurrentApiIsUp: false },
      );
    },
  );

  it('shows a safe error when report generation fails', async () => {
    (WzRequest.genericReq as jest.Mock).mockRejectedValue(new Error('private token or URL'));
    render(<AIAnalysisTab {...alertReference} />);
    fireEvent.click(screen.getByRole('button', { name: 'Generate AI report' }));

    expect(await screen.findByText('AI report is unavailable. Check the backend connection and try again.')).toBeInTheDocument();
    expect(screen.queryByText(/private token or URL/)).toBeNull();
  });
});
