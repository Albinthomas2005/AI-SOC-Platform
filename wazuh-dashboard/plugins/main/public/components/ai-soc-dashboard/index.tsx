import React, { useRef, useState } from 'react';
import {
  EuiBasicTable,
  EuiButton,
  EuiCallOut,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPage,
  EuiPageBody,
  EuiPageContent,
  EuiPanel,
  EuiSpacer,
  EuiStat,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import NavigationService from '../../react-services/navigation-service';
import { WzRequest } from '../../react-services/wz-request';
import { AiSocRecentAlert } from './data';
import { useAiSocOverview } from './use-ai-soc-overview';

const openThreatHuntingAlerts = () => {
  void NavigationService.getInstance().navigateToApp('threat-hunting', {
    path: '#overview/?tab=general&tabView=events',
  });
};

function displayTimestamp(timestamp?: string): string {
  if (!timestamp || Number.isNaN(Date.parse(timestamp))) return '—';
  return new Date(timestamp).toLocaleString();
}

const severityLabels = ['critical', 'high', 'medium', 'low'] as const;

export const AiSocDashboard: React.FC = () => {
  const result = useAiSocOverview();
  const [report, setReport] = useState<{ id: string; text: string }>();
  const [reportError, setReportError] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const requestInFlight = useRef(false);
  const data = result.status === 'available' ? result.data : undefined;
  const failure =
    result.status === 'error' || result.status === 'unavailable'
      ? result.error
      : undefined;

  const generateReport = async (alert: AiSocRecentAlert) => {
    if (requestInFlight.current) return;
    requestInFlight.current = true;
    setReportLoading(true);
    setReportError(false);
    setReport(undefined);
    try {
      const response = await WzRequest.genericReq(
        'POST',
        '/api/ai/generate-report',
        { index: alert.index, id: alert.id },
        { shouldRetry: false, checkCurrentApiIsUp: false },
      );
      const payload = response?.data;
      if (
        payload?.ok !== true ||
        payload.status !== 'ai_generated_unverified' ||
        typeof payload.report !== 'string' ||
        !payload.report.trim()
      ) {
        throw new Error('Invalid report response');
      }
      setReport({ id: alert.id, text: payload.report });
    } catch {
      setReportError(true);
    } finally {
      requestInFlight.current = false;
      setReportLoading(false);
    }
  };

  const columns = [
    {
      field: 'timestamp',
      name: 'Time',
      render: (_: unknown, alert: AiSocRecentAlert) =>
        displayTimestamp(alert.timestamp),
    },
    {
      field: 'title',
      name: 'Alert',
      render: (_: unknown, alert: AiSocRecentAlert) => alert.title || '—',
    },
    {
      field: 'level',
      name: 'Rule level',
      render: (_: unknown, alert: AiSocRecentAlert) => alert.level ?? '—',
    },
    {
      field: 'severity',
      name: 'Severity',
      render: (_: unknown, alert: AiSocRecentAlert) => alert.severity,
    },
    {
      field: 'host',
      name: 'Agent',
      render: (_: unknown, alert: AiSocRecentAlert) => alert.host || '—',
    },
    {
      name: 'Report',
      render: (_: unknown, alert: AiSocRecentAlert) => (
        <EuiButton
          size='s'
          isLoading={reportLoading && report?.id === alert.id}
          isDisabled={reportLoading}
          onClick={() => void generateReport(alert)}
        >
          Generate report
        </EuiButton>
      ),
    },
  ];

  return (
    <EuiPage paddingSize='l'>
      <EuiPageBody>
        <EuiPageContent paddingSize='l'>
          <EuiFlexGroup justifyContent='spaceBetween' alignItems='center'>
            <EuiFlexItem>
              <EuiTitle size='l'>
                <h1>AI SOC Dashboard</h1>
              </EuiTitle>
              <EuiText size='s'>Wazuh alerts from the last 24 hours</EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton
                onClick={openThreatHuntingAlerts}
                iconType='arrowRight'
              >
                Investigate alerts
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size='m' />
          {result.status === 'loading' && (
            <EuiFlexGroup alignItems='center'>
              <EuiFlexItem grow={false}>
                <EuiLoadingSpinner size='m' />
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiText>Loading Wazuh alerts…</EuiText>
              </EuiFlexItem>
            </EuiFlexGroup>
          )}
          {failure && (
            <EuiCallOut
              color={
                failure.kind === 'permission-denied' ||
                failure.kind === 'unauthorized'
                  ? 'warning'
                  : 'danger'
              }
              iconType='alert'
              title={failure.message}
            />
          )}
          {data && (
            <>
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiPanel>
                    <EuiStat
                      title={
                        data.totalRelation === 'gte'
                          ? `≥ ${data.totalAlerts.toLocaleString()}`
                          : data.totalAlerts.toLocaleString()
                      }
                      description='Alerts in the last 24 hours'
                    />
                  </EuiPanel>
                </EuiFlexItem>
                {severityLabels.map(level => (
                  <EuiFlexItem key={level}>
                    <EuiPanel>
                      <EuiStat
                        title={data.severity[level].toLocaleString()}
                        description={`${level} severity`}
                      />
                    </EuiPanel>
                  </EuiFlexItem>
                ))}
              </EuiFlexGroup>
              <EuiSpacer size='m' />
              {data.totalAlerts === 0 ? (
                <EuiEmptyPrompt
                  iconType='search'
                  title={<h2>No alerts in the last 24 hours</h2>}
                  body={<p>Wazuh returned no alerts for this time window.</p>}
                />
              ) : (
                <>
                  <EuiTitle size='s'>
                    <h2>Recent alerts</h2>
                  </EuiTitle>
                  <EuiSpacer size='s' />
                  {data.recentAlerts.length === 0 ? (
                    <EuiEmptyPrompt
                      iconType='search'
                      title={<h3>No recent records returned</h3>}
                      body={
                        <p>
                          The search reported alerts but returned no records to
                          display.
                        </p>
                      }
                    />
                  ) : (
                    <EuiBasicTable
                      items={data.recentAlerts}
                      columns={columns}
                      itemId='id'
                      compressed
                    />
                  )}
                </>
              )}
            </>
          )}
          {reportLoading && (
            <>
              <EuiSpacer size='m' />
              <EuiText>Generating an unverified AI report…</EuiText>
            </>
          )}
          {reportError && (
            <>
              <EuiSpacer size='m' />
              <EuiCallOut
                color='danger'
                iconType='alert'
                title='Report generation is unavailable. Check the AI service and try again.'
              />
            </>
          )}
          {report && (
            <>
              <EuiSpacer size='m' />
              <EuiCallOut
                color='warning'
                iconType='alert'
                title='AI-generated report — unverified'
              >
                <p>
                  Review this draft against the alert evidence before using it.
                </p>
              </EuiCallOut>
              <EuiSpacer size='s' />
              <EuiPanel>
                <EuiText>
                  <pre style={{ whiteSpace: 'pre-wrap' }}>{report.text}</pre>
                </EuiText>
              </EuiPanel>
            </>
          )}
        </EuiPageContent>
      </EuiPageBody>
    </EuiPage>
  );
};
