import '@testing-library/jest-dom';
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { WzRequest } from '../../react-services/wz-request';
import { TrainingPage } from './index';

jest.mock('../../react-services/wz-request', () => ({
  WzRequest: { genericReq: jest.fn() },
}));

const scenario = {
  id: 'ssh-brute-force',
  title: 'Synthetic SSH',
  difficulty: 1,
  category: 'authentication',
  status: 'draft - needs analyst review',
  alert: { rule: { description: 'Synthetic repeated login failures' } },
  evidence: { log_lines: ['198.51.100.8: synthetic failure'], context_notes: ['Synthetic only'] },
};

describe('TrainingPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (WzRequest.genericReq as jest.Mock).mockImplementation((method: string, path: string) => {
      if (path === '/api/training/scenarios') return Promise.resolve({ data: { ok: true, scenarios: [scenario] } });
      if (path.startsWith('/api/training/mitre')) return Promise.resolve({ data: { ok: true, techniques: [{ id: 'T1110.001', name: 'Password Guessing' }] } });
      if (path.includes('/hints')) return Promise.resolve({ data: { ok: true, hints: ['Count failures'], score_impact: 0 } });
      if (method === 'POST') return Promise.resolve({ data: {
        ok: true,
        score: {
          total: 100, maximum: 100,
          verdict: { points: 40, correct: true }, escalation: { points: 20, correct: true },
          mitre: { points: 20, invalid: [] }, report: { points: 20 },
        },
        explanation: 'Expected practice note',
      } });
      return Promise.resolve({ data: { ok: true } });
    });
  });

  it('shows evidence and free hints for a selected queue item', async () => {
    render(<TrainingPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Synthetic SSH' }));
    expect(screen.getByText('Synthetic repeated login failures')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Hint \(free\)/ }));
    expect(await screen.findByText('Hint 1: Count failures')).toBeInTheDocument();
  });

  it('submits a deterministic assessment and displays score feedback', async () => {
    render(<TrainingPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Synthetic SSH' }));
    fireEvent.change(screen.getByPlaceholderText(/Summary:/), {
      target: { value: 'Summary: triage. Evidence: failures. Actions: reviewed. Unknowns: not yet verified.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Submit assessment' }));
    expect(await screen.findByText('Your score: 100/100')).toBeInTheDocument();
    expect(screen.getByText('Expected practice note')).toBeInTheDocument();
    await waitFor(() => expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST', '/api/training/attempts', expect.objectContaining({ scenario_id: scenario.id }),
      { shouldRetry: false, checkCurrentApiIsUp: false },
    ));
  });
});
