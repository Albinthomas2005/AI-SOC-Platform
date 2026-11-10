import React, { useEffect, useRef, useState } from 'react';
import { EuiButton, EuiCallOut, EuiEmptyPrompt, EuiFilePicker, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { WzRequest } from '../../react-services/wz-request';

type Upload = { id?: string; upload_id?: string; title: string; platform: string; line_count: number; uploaded_at: string };
const request = async (method: string, path: string, body?: unknown) => (await WzRequest.genericReq(method, path, body, { shouldRetry: false, checkCurrentApiIsUp: false }) as any)?.data;
const errorMessage = (error: any, fallback: string) => {
  const data = error?.response?.data || error?.data;
  const candidate = [data?.error, data?.message, error?.message].find(
    value => typeof value === 'string' && value.trim() && value !== 'Bad Request',
  );
  return candidate || fallback;
};

export const LabUploads: React.FC = () => {
  const [file, setFile] = useState<File>();
  const [title, setTitle] = useState('');
  const [platform, setPlatform] = useState('linux');
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [samples, setSamples] = useState<Array<{ name: string; title: string }>>([]);
  const [status, setStatus] = useState<any>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const uploadInFlight = useRef(false);

  const refresh = async () => {
    setLoading(true); setError('');
    try {
      const [s, u, p] = await Promise.all([
        request('GET', '/api/phase/lab/status'), request('GET', '/api/phase/lab/uploads'), request('GET', '/api/phase/lab/samples'),
      ]);
      setStatus(s); setUploads(u.uploads || []); setSamples(p.samples || []);
    } catch (e: any) { setError(errorMessage(e, 'Could not load lab upload data')); }
    finally { setLoading(false); }
  };
  useEffect(() => { void refresh(); }, []);

  const uploadFile = async () => {
    if (busy || uploadInFlight.current) return;
    if (!file) { setError('Choose a .log or .txt file'); return; }
    uploadInFlight.current = true;
    setBusy(true); setError('');
    try {
      const bytes = await file.arrayBuffer();
      try {
        new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        setError('File must be valid UTF-8 text');
        return;
      }
      const form = new FormData();
      form.append('file', file, file.name);
      form.append('title', title);
      form.append('platform', platform);
      await request('POST', '/api/phase/lab/uploads', form);
      await refresh();
    } catch (e: any) {
      setError(errorMessage(e, e instanceof TypeError ? 'File must be valid UTF-8 text' : 'Upload failed'));
    } finally { uploadInFlight.current = false; setBusy(false); }
  };
  const loadSample = async (name: string) => {
    setBusy(true); setError('');
    try { await request('POST', `/api/phase/lab/samples/${encodeURIComponent(name)}`); await refresh(); }
    catch (e: any) { setError(errorMessage(e, 'Sample upload failed')); }
    finally { setBusy(false); }
  };
  const remove = async (upload: Upload) => {
    const uploadId = upload.id || upload.upload_id;
    if (!uploadId) { setError('This upload record has no identifier. Refresh the page and try again.'); return; }
    if (!window.confirm('Delete this platform upload record? Alerts already created in Wazuh cannot be removed by this tool.')) return;
    setBusy(true); setError('');
    try { await request('DELETE', `/api/phase/lab/uploads/${encodeURIComponent(uploadId)}`); await refresh(); }
    catch (e: any) { setError(errorMessage(e, 'Delete failed')); }
    finally { setBusy(false); }
  };

  return <div className="wz-padding-16">
    <EuiTitle size="m"><h1>Upload logs</h1></EuiTitle><EuiSpacer />
    <EuiCallOut color="warning" title="Lab use only. Do not upload real employer or customer data. Windows logs are not supported here: Windows alerts need a real Wazuh agent." />
    <EuiSpacer />
    <EuiPanel><EuiTitle size="s"><h2>Wazuh setup status</h2></EuiTitle>
      {loading ? <p role="status">Loading status…</p> : status ? <><EuiText><p>Injection: {status.injection_enabled ? 'enabled' : 'disabled'} · target exists: {status.target_exists ? 'yes' : 'no'} · writable: {status.target_writable ? 'yes' : 'no'}</p><p>Wazuh read confirmed: {status.wazuh_read_confirmed ? 'yes' : 'no'} · {status.wazuh_read_reason || 'No confirmation details available'}</p><ul>{(status.setup_needed || []).map((item: string) => <li key={item}>{item}</li>)}</ul></EuiText></> : <EuiEmptyPrompt title={<h3>Status unavailable</h3>} />}
    </EuiPanel><EuiSpacer />
    <EuiPanel><EuiTitle size="s"><h2>Upload a log file</h2></EuiTitle>
      <EuiFormRow label="File (.log or .txt, up to 1 MiB and 2000 lines)"><EuiFilePicker initialPromptText="Choose a log file" accept=".log,.txt,text/plain" onChange={files => setFile(files?.[0])} /></EuiFormRow>
      <EuiFormRow label="Title"><input className="euiFieldText" value={title} maxLength={120} onChange={event => setTitle(event.target.value)} /></EuiFormRow>
      <EuiFormRow label="Platform"><EuiSelect value={platform} options={['linux', 'syslog', 'web', 'windows'].map(value => ({ value, text: value }))} onChange={event => setPlatform(event.target.value)} /></EuiFormRow>
      <EuiButton isLoading={busy} isDisabled={busy || !file || !title.trim()} onClick={() => void uploadFile()}>Upload logs</EuiButton>
    </EuiPanel><EuiSpacer />
    <EuiPanel><EuiTitle size="s"><h2>Sample packs</h2></EuiTitle>{loading ? <p role="status">Loading samples…</p> : samples.length ? samples.map(sample => <EuiButton key={sample.name} isLoading={busy} isDisabled={busy} onClick={() => void loadSample(sample.name)}>{sample.title}</EuiButton>) : <EuiEmptyPrompt title={<h3>No samples available</h3>} />}</EuiPanel><EuiSpacer />
    <EuiPanel><EuiTitle size="s"><h2>Your uploads</h2></EuiTitle>{loading ? <p role="status">Loading uploads…</p> : uploads.length ? uploads.map(upload => { const uploadId = upload.id || upload.upload_id; return <div key={uploadId || `${upload.title}-${upload.uploaded_at}`}><EuiText><p>{upload.title} · {upload.platform} · {upload.line_count} lines · {new Date(upload.uploaded_at).toLocaleString()}</p></EuiText><EuiButton color="danger" size="s" isDisabled={busy || !uploadId} onClick={() => void remove(upload)}>Delete record</EuiButton><EuiSpacer size="s" /></div>; }) : <EuiEmptyPrompt title={<h3>No uploads yet</h3>} body={<p>Upload a lab log or load a sample pack.</p>} />}</EuiPanel>
    {error && <><EuiSpacer /><EuiCallOut color="danger" title={error} /></>}
  </div>;
};

export default LabUploads;
