import React from 'react';
import { render, screen } from '@testing-library/react';
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
});
