import React, { useState } from 'react';
import { EuiButton, EuiCallOut, EuiCodeBlock, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiTabs, EuiTab, EuiTextArea, EuiTitle } from '@elastic/eui';
import { WzRequest } from '../../react-services/wz-request';

const tabs = ['Correlation', 'Incidents', 'Threat intel', 'Hunting', 'Audit', 'Assistant'];
const emptyRefs = '[{"index":"wazuh-alerts-4.x-2026.11.08","id":"replace-with-alert-id"}]';

export const PhaseWorkbench: React.FC = () => {
  const [tab, setTab] = useState(0);
  const [refs, setRefs] = useState(emptyRefs);
  const [question, setQuestion] = useState('');
  const [result, setResult] = useState<any>();
  const [error, setError] = useState('');
  const [incidents, setIncidents] = useState<any[]>([]);
  const [incidentId, setIncidentId] = useState('');
  const [status, setStatus] = useState('Investigating');
  const [note, setNote] = useState('');

  const call = async (method: string, path: string, body?: any) => {
    setError('');
    try {
      const response: any = await WzRequest.genericReq(method, path, body, { shouldRetry: false, checkCurrentApiIsUp: false });
      setResult(response?.data);
      return response?.data;
    } catch (e: any) {
      setError(e?.response?.data?.error || e?.message || 'Request failed');
      return undefined;
    }
  };
  const parseRefs = () => {
    try { return JSON.parse(refs); } catch { setError('Alert references must be valid JSON'); return undefined; }
  };
  const loadIncidents = async () => {
    const data = await call('GET', '/api/phase/incidents');
    if (Array.isArray(data?.incidents)) setIncidents(data.incidents);
  };
  const act = async () => {
    const alert_refs = parseRefs();
    if (tab === 0 && alert_refs) await call('POST', '/api/phase/correlations/run', { alert_refs });
    if (tab === 2 && alert_refs) await call('POST', '/api/phase/threat-intel/lookup', { alert_refs });
    if (tab === 3) await call('POST', '/api/hunts/run', { question });
    if (tab === 4) await call('GET', '/api/phase/admin/audit');
    if (tab === 5) await call('POST', '/api/phase/assistant/chat', { question, evidence_refs: parseRefs() });
    if (tab === 1) await loadIncidents();
  };
  const createIncident = async () => {
    const correlation = result?.group || result?.correlation_group || result?.groups?.[0];
    if (correlation) {
      await call('POST', '/api/phase/incidents', { correlation_group: correlation, title: 'Correlated alert investigation' });
    } else {
      const alert_refs = parseRefs();
      if (alert_refs) await call('POST', '/api/phase/correlations/run', { alert_refs });
    }
  };

  return <div className="wz-padding-16">
    <EuiTitle size="m"><h1>Security Operations Workbench</h1></EuiTitle><EuiSpacer />
    <EuiTabs>{tabs.map((label, index) => <EuiTab key={label} onClick={() => { setTab(index); setError(''); }} isSelected={tab === index}>{label}</EuiTab>)}</EuiTabs>
    <EuiSpacer />
    <EuiPanel>
      {(tab === 0 || tab === 2 || tab === 5) && <EuiFormRow label="Wazuh alert references (JSON)"><EuiTextArea value={refs} onChange={e => setRefs(e.target.value)} rows={3} /></EuiFormRow>}
      {(tab === 3 || tab === 5) && <EuiFormRow label="Question"><EuiTextArea value={question} onChange={e => setQuestion(e.target.value)} rows={3} /></EuiFormRow>}
      {tab === 1 && <>
        <EuiButton onClick={loadIncidents}>Refresh incidents</EuiButton><EuiSpacer />
        <EuiSelect aria-label="Incident" options={incidents.map(i => ({ value: i.incident_id, text: `${i.title} · ${i.status}` }))} value={incidentId} onChange={e => { setIncidentId(e.target.value); if (e.target.value) void call('GET', `/api/phase/incidents/${e.target.value}`); }} prepend="Incident" />
        <EuiSpacer />
        <EuiSelect aria-label="Status" options={['New', 'Investigating', 'Escalated', 'Contained', 'Resolved', 'Closed'].map(value => ({ value, text: value }))} value={status} onChange={e => setStatus(e.target.value)} prepend="Status" />
        <EuiButton disabled={!incidentId} onClick={() => call('POST', `/api/phase/incidents/${incidentId}/status`, { status })}>Update status</EuiButton>
        <EuiFormRow label="Incident note"><EuiTextArea value={note} onChange={e => setNote(e.target.value)} /></EuiFormRow>
        <EuiButton disabled={!incidentId || !note.trim()} onClick={() => call('POST', `/api/phase/incidents/${incidentId}/notes`, { note })}>Add note</EuiButton>
        <EuiButton onClick={createIncident}>Create incident from correlation result</EuiButton>
        {result?.incident && <><EuiSpacer /><EuiCodeBlock language="json">{JSON.stringify(result.incident, null, 2)}</EuiCodeBlock></>}
      </>}
      {tab !== 1 && <EuiButton fill onClick={act}>{tab === 0 ? 'Build correlation timeline' : tab === 2 ? 'Look up threat indicators' : tab === 3 ? 'Run hunt' : tab === 4 ? 'Load audit events' : 'Ask assistant'}</EuiButton>}
      {error && <><EuiSpacer /><EuiCallOut color="danger" title={error} /></>}
      {result && <><EuiSpacer /><EuiCodeBlock language="json" isCopyable>{JSON.stringify(result, null, 2)}</EuiCodeBlock></>}
    </EuiPanel>
  </div>;
};

export default PhaseWorkbench;
