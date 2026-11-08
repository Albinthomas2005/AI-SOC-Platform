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
  EuiTextArea,
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
type AnalystDecision = 'unreviewed' | 'approved' | 'edited' | 'rejected';
type ReportState = {
  id: string;
  analysisId: string;
  text: string;
  decision: AnalystDecision;
  decisionNote?: string;
  decidedAt?: string;
};

export const AiSocDashboard: React.FC = () => {
  const result = useAiSocOverview();
  const [report, setReport] = useState<ReportState>();
  const [reportError, setReportError] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [decisionLoading, setDecisionLoading] = useState(false);
  const [decisionError, setDecisionError] = useState(false);
  const [editingReport, setEditingReport] = useState(false);
  const [editedText, setEditedText] = useState('');
  const [decisionNote, setDecisionNote] = useState('');
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
        typeof payload.analysis_id !== 'string' ||
        !/^[0-9a-f]{32}$/.test(payload.analysis_id) ||
        payload.decision !== 'unreviewed' ||
        payload.decision_label !== 'AI draft - not reviewed' ||
        typeof payload.report !== 'string' ||
        !payload.report.trim()
      ) {
        throw new Error('Invalid report response');
      }
      setReport({
        id: alert.id,
        analysisId: payload.analysis_id,
        text: payload.report,
        decision: 'unreviewed',
      });
      setEditedText(payload.report);
      setDecisionNote('');
      setEditingReport(false);
    } catch {
      setReportError(true);
    } finally {
      requestInFlight.current = false;
      setReportLoading(false);
    }
  };

  const recordDecision = async (decision: 'approved' | 'edited' | 'rejected') => {
    if (!report || decisionLoading) return;
    setDecisionLoading(true);
    setDecisionError(false);
    try {
      const body: Record<string, string> = {
        analysis_id: report.analysisId,
        decision,
        note: decisionNote,
      };
      if (decision === 'edited') body.edited_analysis = editedText;
      const response = await WzRequest.genericReq(
        'POST',
        '/api/ai/analysis/decision',
        body,
        { shouldRetry: false, checkCurrentApiIsUp: false },
      );
      const payload = response?.data;
      if (
        payload?.ok !== true ||
        payload.analysis_id !== report.analysisId ||
        payload.decision !== decision ||
        typeof payload.decided_at !== 'string'
      ) {
        throw new Error('Invalid analyst decision response');
      }
      setReport(current =>
        current
          ? {
              ...current,
              text:
                decision === 'edited' && typeof payload.edited_analysis === 'string'
                  ? payload.edited_analysis
                  : current.text,
              decision,
              decisionNote: payload.note,
              decidedAt: payload.decided_at,
            }
          : current,
      );
      setEditingReport(false);
    } catch {
      setDecisionError(true);
    } finally {
      setDecisionLoading(false);
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
                color={report.decision === 'unreviewed' ? 'warning' : 'success'}
                iconType='alert'
                title={
                  report.decision === 'unreviewed'
                    ? 'AI draft - not reviewed'
                    : `Analyst decision: ${report.decision}`
                }
              >
                <p>
                  AI-generated output is unverified. Review it against the alert
                  evidence before using it.
                </p>
                {report.decisionNote && <p>Analyst note: {report.decisionNote}</p>}
                {report.decidedAt && <p>Decision time: {displayTimestamp(report.decidedAt)}</p>}
              </EuiCallOut>
              <EuiSpacer size='s' />
              <EuiPanel>
                {editingReport ? (
                  <EuiTextArea
                    aria-label='Edit AI report'
                    fullWidth
                    rows={12}
                    value={editedText}
                    onChange={event => setEditedText(event.target.value)}
                  />
                ) : (
                  <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                    {report.text}
                  </pre>
                )}
                <EuiSpacer size='s' />
                <EuiTextArea
                  aria-label='Analyst decision note'
                  placeholder='Optional analyst note'
                  fullWidth
                  rows={2}
                  value={decisionNote}
                  onChange={event => setDecisionNote(event.target.value)}
                />
                <EuiSpacer size='s' />
                <EuiFlexGroup gutterSize='s' responsive={false}>
                  {editingReport ? (
                    <>
                      <EuiFlexItem grow={false}>
                        <EuiButton
                          isLoading={decisionLoading}
                          isDisabled={decisionLoading || !editedText.trim()}
                          onClick={() => void recordDecision('edited')}
                        >
                          Save edited report
                        </EuiButton>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButton onClick={() => setEditingReport(false)}>Cancel</EuiButton>
                      </EuiFlexItem>
                    </>
                  ) : (
                    <>
                      <EuiFlexItem grow={false}>
                        <EuiButton
                          isLoading={decisionLoading}
                          isDisabled={decisionLoading}
                          onClick={() => void recordDecision('approved')}
                        >
                          Approve
                        </EuiButton>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButton
                          isDisabled={decisionLoading}
                          onClick={() => {
                            setEditedText(report.text);
                            setEditingReport(true);
                          }}
                        >
                          Edit
                        </EuiButton>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButton
                          isLoading={decisionLoading}
                          isDisabled={decisionLoading}
                          onClick={() => void recordDecision('rejected')}
                        >
                          Reject
                        </EuiButton>
                      </EuiFlexItem>
                    </>
                  )}
                </EuiFlexGroup>
                {decisionError && (
                  <EuiCallOut
                    color='danger'
                    iconType='alert'
                    title='The analyst decision could not be saved.'
                  />
                )}
              </EuiPanel>
            </>
          )}
        </EuiPageContent>
      </EuiPageBody>
    </EuiPage>
  );
};
