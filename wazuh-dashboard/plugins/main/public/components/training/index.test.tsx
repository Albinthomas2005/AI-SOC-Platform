import '@testing-library/jest-dom';
import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { WzRequest } from '../../react-services/wz-request';
import { TrainingPage } from './index';
import { TrainingPageErrorBoundary } from './training-page-boundary';

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
      if (path.includes('/coaching')) return Promise.resolve({ data: { ok: true, coaching: {
        what_was_good: 'Cited the event', what_was_missed: 'No related logs',
        one_thing_to_practise: 'State the unknowns',
      } } });
      if (method === 'POST') return Promise.resolve({ data: {
        ok: true,
        score: {
          total: 100, maximum: 100,
          verdict: { points: 40, correct: true }, escalation: { points: 20, correct: true },
          mitre: { points: 20, invalid: [] }, report: { points: 20 },
        },
        explanation: 'Expected practice note',
        attempt_id: 'training-attempt-id',
        analyst: { verdict: 'true_positive', escalate: true, mitre_ids: ['T1110.001'] },
        ai: { verdict: 'true_positive', escalate: true, mitre_ids: ['T1110.001'] },
        expected: { verdict: 'true_positive', escalate: true, mitre_ids: ['T1110.001'] },
      } });
      return Promise.resolve({ data: { ok: true } });
    });
  });

  it('renders the scenario list from a mocked request', async () => {
    render(<TrainingPage />);
    await screen.findByRole('button', { name: 'Synthetic SSH' });
    const list = screen.getByRole('list', { name: 'Training scenarios' });
    expect(within(list).getByRole('button', { name: 'Synthetic SSH' })).toBeInTheDocument();
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'GET', '/api/training/scenarios', undefined,
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
  });

  it('shows a visible error when the scenario request fails', async () => {
    (WzRequest.genericReq as jest.Mock).mockImplementation((method: string, path: string) =>
      path === '/api/training/scenarios'
        ? Promise.reject(new Error('synthetic fetch failure'))
        : Promise.resolve({ data: { ok: true, progress: { attempts: [] }, techniques: [] } }),
    );
    render(<TrainingPage />);
    expect(await screen.findByText('Training service is unavailable. Try again.')).toBeInTheDocument();
  });

  it('replaces a rendering crash with the boundary message', async () => {
    const BrokenPage: React.FC = () => { throw new Error('synthetic render failure'); };
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});
    render(<TrainingPageErrorBoundary><BrokenPage /></TrainingPageErrorBoundary>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Training could not be displayed');
    error.mockRestore();
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
    expect(await screen.findByText('Cited the event')).toBeInTheDocument();
    await waitFor(() => expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST', '/api/training/attempts', expect.objectContaining({ scenario_id: scenario.id }),
      { shouldRetry: false, checkCurrentApiIsUp: false },
    ));
  });

  it('starts a timed eight-case shift without rendering hints', async () => {
    const shiftScenarios = Array.from({ length: 8 }, (_, index) => ({
      ...scenario, id: `shift-case-${index}`, title: `Shift case ${index + 1}`,
    }));
    (WzRequest.genericReq as jest.Mock).mockImplementation((method: string, path: string) => {
      if (path === '/api/training/scenarios') return Promise.resolve({ data: { ok: true, scenarios: [scenario] } });
      if (path === '/api/training/progress') return Promise.resolve({ data: { ok: true, progress: { attempts: [], attempt_count: 0 } } });
      if (path.startsWith('/api/training/mitre')) return Promise.resolve({ data: { ok: true, techniques: [] } });
      if (method === 'POST' && path === '/api/training/shifts') return Promise.resolve({ data: {
        ok: true, shift_id: 'shift-id', duration_seconds: 1200,
        deadline_at: new Date(Date.now() + 1200000).toISOString(), scenarios: shiftScenarios,
      } });
      return Promise.resolve({ data: { ok: true } });
    });
    render(<TrainingPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Start 8-case timed shift' }));
    expect(await screen.findByText(/Shift in progress/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Hint \(free\)/ })).not.toBeInTheDocument();
    expect(screen.getByText('Shift case 1')).toBeInTheDocument();
  });
});
