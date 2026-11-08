import React from 'react';
import { EuiTabbedContent } from '@elastic/eui';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { WzRequest } from '../../../../react-services/wz-request';
import {
  createAIAnalysisTabs,
  createModuleAIAnalysisTabs,
} from './ai-analysis-tabs';

jest.mock('../../../../react-services/wz-request', () => ({
  WzRequest: { genericReq: jest.fn() },
}));

const sampleAlerts = [
  {
    _index: 'wazuh-alerts-4.x-test',
    _id: 'rootcheck-510',
    _source: {
      rule: { id: '510', description: 'Trojaned version of file' },
      full_log: 'private rootcheck log',
    },
  },
  {
    _index: 'wazuh-alerts-4.x-test',
    _id: 'sudo-5402',
    _source: { rule: { id: '5402', description: 'sudo to root' } },
  },
];

describe('shared AI Analysis document tabs', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (WzRequest.genericReq as jest.Mock).mockRejectedValue(new Error('unauthorized'));
  });

  it.each([
    ['Threat Hunting Events', 'threat-hunting', sampleAlerts[0]],
    ['Malware Detection Events', 'pm', sampleAlerts[0]],
    ['MITRE Events', 'mitre', sampleAlerts[1]],
    ['MITRE technique recent-events flyout', 'flyout', sampleAlerts[1]],
  ])('%s renders AI Analysis for alert rule %s', async (viewer, moduleId, alert) => {
    const tabs = moduleId === 'flyout'
      ? createAIAnalysisTabs(alert)
      : createModuleAIAnalysisTabs(moduleId, alert);
    render(
      <EuiTabbedContent
        initialSelectedTab={tabs[0]}
        tabs={[
          { id: 'table', name: 'Table', content: <div>Alert table</div> },
          ...tabs,
        ]}
      />,
    );
    fireEvent.click(screen.getByRole('tab', { name: 'AI Analysis' }));

    fireEvent.click(screen.getByRole('button', { name: 'Generate AI report' }));
    expect(await screen.findByText('AI report is unavailable. Check the backend connection and try again.')).toBeInTheDocument();
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST',
      '/api/ai/generate-report',
      { index: alert._index, id: alert._id },
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
    expect(JSON.stringify(WzRequest.genericReq.mock.calls)).not.toContain('full_log');
  });
});
