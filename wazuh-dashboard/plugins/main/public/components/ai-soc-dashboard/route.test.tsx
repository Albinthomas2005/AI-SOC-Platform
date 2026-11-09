import '@testing-library/jest-dom';
import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Switch } from 'react-router-dom';
import { aiSocDashboardRoute } from './route';

jest.mock('../common/data-source', () => ({
  AlertsDataSourceRepository: jest.fn(),
  ThreatHuntingDataSource: jest.fn(),
  useDataSource: jest.fn(() => ({
    isLoading: true,
    dataSource: undefined,
    error: null,
    fetchData: jest.fn(),
  })),
}));

describe('AI SOC dashboard route', () => {
  it('mounts AiSocDashboard as a component so its hooks have a React dispatcher', () => {
    render(
      <MemoryRouter initialEntries={['/ai-soc-dashboard']}>
        <Switch>{aiSocDashboardRoute}</Switch>
      </MemoryRouter>,
    );
    expect(screen.getByRole('heading', { name: 'AI SOC Dashboard' })).toBeInTheDocument();
  });
});
