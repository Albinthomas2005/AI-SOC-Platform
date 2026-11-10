import React from 'react';
import { render, screen } from '@testing-library/react';
import { WzRequest } from '../../../react-services/wz-request';
import { LabUploads } from './index';

jest.mock('../../../react-services/wz-request', () => ({
  WzRequest: { genericReq: jest.fn().mockRejectedValue(new Error('offline')) },
}));

describe('LabUploads', () => {
  it('shows the upload notice, loading state, and a readable error state', async () => {
    render(<LabUploads />);
    expect(screen.getByRole('heading', { name: 'Upload logs' })).toBeInTheDocument();
    expect(screen.getByText(/Lab use only/)).toBeInTheDocument();
    expect(screen.getAllByRole('status').length).toBeGreaterThan(0);
    expect(await screen.findByText('Could not load lab upload data')).toBeInTheDocument();
  });

  it('does not issue a delete request when an upload has no identifier', async () => {
    (WzRequest.genericReq as jest.Mock).mockImplementation((_method, path) => {
      if (path === '/api/phase/lab/status') return Promise.resolve({ data: {} });
      if (path === '/api/phase/lab/uploads') return Promise.resolve({ data: { uploads: [
        { title: 'Legacy upload', platform: 'linux', line_count: 1, uploaded_at: '2026-11-10T00:00:00Z' },
      ] } });
      if (path === '/api/phase/lab/samples') return Promise.resolve({ data: { samples: [] } });
      return Promise.resolve({ data: {} });
    });

    render(<LabUploads />);
    expect(await screen.findByText(/Legacy upload/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete record' })).toBeDisabled();
    expect(WzRequest.genericReq).not.toHaveBeenCalledWith(
      'DELETE', expect.stringContaining('/api/phase/lab/uploads/undefined'),
      expect.anything(), expect.anything(),
    );
  });
});
