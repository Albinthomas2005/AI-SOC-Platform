import '@testing-library/jest-dom';
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { useDataSource } from '../common/data-source';
import { useAiSocOverview } from './use-ai-soc-overview';

jest.mock('../common/data-source', () => ({
  AlertsDataSourceRepository: jest.fn(),
  ThreatHuntingDataSource: jest.fn(),
  useDataSource: jest.fn(),
}));

const response = {
  hits: { total: { value: 0 }, hits: [] },
  aggregations: {
    severity: {
      buckets: {
        critical: { doc_count: 0 },
        high: { doc_count: 0 },
        medium: { doc_count: 0 },
        low: { doc_count: 0 },
      },
    },
  },
};
const Probe: React.FC = () => {
  const result = useAiSocOverview();
  return (
    <div>
      <span data-testid='status'>{result.status}</span>
      {result.status === 'available' && (
        <span data-testid='total'>{result.data.totalAlerts}</span>
      )}
    </div>
  );
};

describe('useAiSocOverview', () => {
  beforeEach(() => jest.clearAllMocks());
  it('queries the configured Wazuh alert data source with a 24-hour window and numeric severity buckets', async () => {
    const fetchData = jest.fn().mockResolvedValue(response);
    (useDataSource as jest.Mock).mockReturnValue({
      isLoading: false,
      dataSource: {},
      error: null,
      fetchData,
    });
    render(<Probe />);
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('available'),
    );
    expect(screen.getByTestId('total')).toHaveTextContent('0');
    expect(fetchData).toHaveBeenCalledWith(
      expect.objectContaining({
        query: { language: 'kuery', query: '' },
        dateRange: { from: 'now-24h', to: 'now' },
        pagination: { pageIndex: 0, pageSize: 5 },
        sorting: { columns: [{ id: 'timestamp', direction: 'desc' }] },
        aggs: expect.objectContaining({ severity: expect.any(Object) }),
      }),
    );
  });
  it.each([401, 403, 503])(
    'surfaces a safe %i search failure',
    async status => {
      const fetchData = jest.fn().mockRejectedValue({ status });
      (useDataSource as jest.Mock).mockReturnValue({
        isLoading: false,
        dataSource: {},
        error: null,
        fetchData,
      });
      render(<Probe />);
      await waitFor(() =>
        expect(screen.getByTestId('status')).toHaveTextContent('error'),
      );
    },
  );
  it('shows unavailable when no compatible saved alert pattern exists', async () => {
    (useDataSource as jest.Mock).mockReturnValue({
      isLoading: false,
      dataSource: undefined,
      error: 'Alerts index pattern not found',
      fetchData: jest.fn(),
    });
    render(<Probe />);
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('unavailable'),
    );
  });
});
