import React, { useRef, useState } from 'react';
import {
  EuiButton,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiMarkdownFormat,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { WzRequest } from '../../../../react-services/wz-request';

interface AIAnalysisTabProps {
  index: string;
  id: string;
}

type Decision = 'unreviewed' | 'approved' | 'edited' | 'rejected';

const AI_ANALYSIS_ERROR =
  'AI report is unavailable. Check the backend connection and try again.';

export const AIAnalysisTab = ({ index, id }: AIAnalysisTabProps) => {
  const [report, setReport] = useState<string>();
  const [analysisId, setAnalysisId] = useState<string>();
  const [decision, setDecision] = useState<Decision>('unreviewed');
  const [isLoading, setIsLoading] = useState(false);
  const [decisionLoading, setDecisionLoading] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [decisionError, setDecisionError] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editedReport, setEditedReport] = useState('');
  const [decisionNote, setDecisionNote] = useState('');
  const requestInFlight = useRef(false);

  const generateReport = async () => {
    if (requestInFlight.current) return;

    requestInFlight.current = true;
    setIsLoading(true);
    setHasError(false);
    setReport(undefined);
    setAnalysisId(undefined);

    try {
      const response = await WzRequest.genericReq(
        'POST',
        '/api/ai/generate-report',
        { index, id },
        { shouldRetry: false, checkCurrentApiIsUp: false },
      );
      const result = response?.data;
      if (
        result?.ok !== true ||
        result.status !== 'ai_generated_unverified' ||
        typeof result.analysis_id !== 'string' ||
        !/^[0-9a-f]{32}$/.test(result.analysis_id) ||
        result.decision !== 'unreviewed' ||
        typeof result.report !== 'string' ||
        !result.report.trim()
      ) {
        throw new Error('Invalid AI report response');
      }

      setAnalysisId(result.analysis_id);
      setReport(result.report);
      setEditedReport(result.report);
      setDecision('unreviewed');
      setDecisionNote('');
      setDecisionError(false);
      setIsEditing(false);
    } catch {
      setHasError(true);
    } finally {
      requestInFlight.current = false;
      setIsLoading(false);
    }
  };

  const recordDecision = async (nextDecision: Exclude<Decision, 'unreviewed'>) => {
    if (!analysisId || decisionLoading) return;
    setDecisionLoading(true);
    setDecisionError(false);
    try {
      const body: Record<string, string> = {
        analysis_id: analysisId,
        decision: nextDecision,
        note: decisionNote,
      };
      if (nextDecision === 'edited') body.edited_analysis = editedReport;
      const response = await WzRequest.genericReq(
        'POST',
        '/api/ai/analysis/decision',
        body,
        { shouldRetry: false, checkCurrentApiIsUp: false },
      );
      const result = response?.data;
      if (
        result?.ok !== true ||
        result.analysis_id !== analysisId ||
        result.decision !== nextDecision ||
        typeof result.decided_at !== 'string'
      ) {
        throw new Error('Invalid decision response');
      }
      if (nextDecision === 'edited' && typeof result.edited_analysis === 'string') {
        setReport(result.edited_analysis);
      }
      setDecision(nextDecision);
      setIsEditing(false);
    } catch {
      setDecisionError(true);
    } finally {
      setDecisionLoading(false);
    }
  };

  return (
    <EuiFlexGroup direction='column' alignItems='flexStart' gutterSize='m'>
      <EuiFlexItem grow={false}>
        <EuiText size='s'>
          Generate a report from this alert, then review and record your decision.
        </EuiText>
        <EuiSpacer size='m' />
        <EuiButton onClick={() => void generateReport()} isLoading={isLoading} isDisabled={isLoading}>
          Generate AI report
        </EuiButton>
      </EuiFlexItem>

      {isLoading && <EuiFlexItem grow={false}><EuiText size='s'>Generating an unverified AI report…</EuiText></EuiFlexItem>}
      {hasError && <EuiFlexItem><EuiCallOut color='danger' iconType='alert' title={AI_ANALYSIS_ERROR} /></EuiFlexItem>}
      {report !== undefined && (
        <EuiFlexItem>
          <EuiCallOut color={decision === 'unreviewed' ? 'warning' : 'success'} title={decision === 'unreviewed' ? 'AI draft - not reviewed' : `Analyst decision: ${decision}`}>
            <p>AI-generated output is unverified. Review it against the alert evidence before using it.</p>
          </EuiCallOut>
          <EuiSpacer size='s' />
          <EuiPanel paddingSize='m'>
            <EuiTitle size='s'><h3>Investigation report</h3></EuiTitle>
            <EuiSpacer size='s' />
            {isEditing ? (
              <EuiTextArea aria-label='Edit AI report' fullWidth rows={12} value={editedReport} onChange={event => setEditedReport(event.target.value)} />
            ) : <EuiMarkdownFormat>{report}</EuiMarkdownFormat>}
            <EuiSpacer size='s' />
            <EuiTextArea aria-label='Analyst decision note' placeholder='Optional analyst note' fullWidth rows={2} value={decisionNote} onChange={event => setDecisionNote(event.target.value)} />
            <EuiSpacer size='s' />
            <EuiFlexGroup gutterSize='s' responsive={false}>
              {isEditing ? (
                <>
                  <EuiFlexItem grow={false}><EuiButton isLoading={decisionLoading} isDisabled={decisionLoading || !editedReport.trim()} onClick={() => void recordDecision('edited')}>Save edited report</EuiButton></EuiFlexItem>
                  <EuiFlexItem grow={false}><EuiButton isDisabled={decisionLoading} onClick={() => setIsEditing(false)}>Cancel</EuiButton></EuiFlexItem>
                </>
              ) : (
                <>
                  <EuiFlexItem grow={false}><EuiButton isLoading={decisionLoading} isDisabled={decisionLoading} onClick={() => void recordDecision('approved')}>Approve</EuiButton></EuiFlexItem>
                  <EuiFlexItem grow={false}><EuiButton isDisabled={decisionLoading} onClick={() => { setEditedReport(report); setIsEditing(true); }}>Edit</EuiButton></EuiFlexItem>
                  <EuiFlexItem grow={false}><EuiButton isLoading={decisionLoading} isDisabled={decisionLoading} onClick={() => void recordDecision('rejected')}>Reject</EuiButton></EuiFlexItem>
                </>
              )}
            </EuiFlexGroup>
            {decisionError && <><EuiSpacer size='s' /><EuiCallOut color='danger' title='The analyst decision could not be saved.' /></>}
          </EuiPanel>
        </EuiFlexItem>
      )}
    </EuiFlexGroup>
  );
};
