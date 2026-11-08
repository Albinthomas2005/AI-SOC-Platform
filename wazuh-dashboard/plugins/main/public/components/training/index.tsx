import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiCallOut,
  EuiCodeBlock,
  EuiFieldSearch,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPage,
  EuiPageBody,
  EuiPageContent,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { WzRequest } from '../../react-services/wz-request';

type Scenario = {
  id: string;
  title: string;
  difficulty: number;
  category: string;
  status: string;
  alert: Record<string, unknown>;
  evidence: { log_lines: string[]; context_notes: string[] };
};
type Technique = { id: string; name: string };

export const TrainingPage: React.FC = () => {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selected, setSelected] = useState<Scenario>();
  const [difficulty, setDifficulty] = useState('all');
  const [category, setCategory] = useState('all');
  const [completed, setCompleted] = useState<string[]>([]);
  const [hintLevel, setHintLevel] = useState(0);
  const [hints, setHints] = useState<string[]>([]);
  const [verdict, setVerdict] = useState('true_positive');
  const [escalate, setEscalate] = useState(true);
  const [report, setReport] = useState('');
  const [techniqueSearch, setTechniqueSearch] = useState('');
  const [techniques, setTechniques] = useState<Technique[]>([]);
  const [mitreIds, setMitreIds] = useState<string[]>([]);
  const [result, setResult] = useState<any>();
  const [error, setError] = useState(false);
  const [startedAt, setStartedAt] = useState(Date.now());

  useEffect(() => {
    let active = true;
    WzRequest.genericReq('GET', '/api/training/scenarios', undefined, { shouldRetry: false, checkCurrentApiIsUp: false })
      .then((response: any) => {
        if (active && response?.data?.ok && Array.isArray(response.data.scenarios)) setScenarios(response.data.scenarios);
        else if (active) setError(true);
      }).catch(() => active && setError(true));
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    const query = encodeURIComponent(techniqueSearch);
    WzRequest.genericReq('GET', `/api/training/mitre?q=${query}`, undefined, { shouldRetry: false, checkCurrentApiIsUp: false })
      .then((response: any) => active && setTechniques(response?.data?.techniques || []))
      .catch(() => active && setTechniques([]));
    return () => { active = false; };
  }, [techniqueSearch]);

  const categories = useMemo(() => Array.from(new Set(scenarios.map(s => s.category))).sort(), [scenarios]);
  const visible = scenarios.filter(s => (difficulty === 'all' || String(s.difficulty) === difficulty) && (category === 'all' || s.category === category));

  const selectScenario = (scenario: Scenario) => {
    setSelected(scenario);
    setResult(undefined);
    setHints([]);
    setHintLevel(0);
    setVerdict('true_positive');
    setEscalate(true);
    setMitreIds([]);
    setReport('');
    setStartedAt(Date.now());
  };

  const requestHint = async () => {
    if (!selected) return;
    try {
      const next = hintLevel + 1;
      const response: any = await WzRequest.genericReq('GET', `/api/training/scenarios/${encodeURIComponent(selected.id)}/hints?level=${next}`, undefined, { shouldRetry: false, checkCurrentApiIsUp: false });
      setHints(response?.data?.hints || []);
      setHintLevel(next);
    } catch { setError(true); }
  };

  const submitAttempt = async () => {
    if (!selected) return;
    setError(false);
    try {
      const response: any = await WzRequest.genericReq('POST', '/api/training/attempts', {
        scenario_id: selected.id,
        verdict,
        escalate,
        mitre_ids: mitreIds,
        report_text: report,
        time_spent: Math.max(0, Math.floor((Date.now() - startedAt) / 1000)),
      }, { shouldRetry: false, checkCurrentApiIsUp: false });
      if (!response?.data?.ok) throw new Error('Invalid score response');
      setResult(response.data);
      setCompleted(current => current.includes(selected.id) ? current : [...current, selected.id]);
    } catch { setError(true); }
  };

  return (
    <EuiPage paddingSize='l'><EuiPageBody><EuiPageContent paddingSize='l'>
      <EuiTitle size='l'><h1>Analyst Training</h1></EuiTitle>
      <EuiText size='s'><p>Work from the supplied synthetic evidence. Unverified facts are not yet verified.</p></EuiText>
      <EuiSpacer />
      {error && <EuiCallOut color='danger' title='Training service is unavailable. Try again.' />}
      <EuiFlexGroup gutterSize='l' responsive>
        <EuiFlexItem grow={1}>
          <EuiPanel>
            <EuiTitle size='s'><h2>Scenario queue</h2></EuiTitle>
            <EuiFormRow label='Difficulty'><EuiSelect value={difficulty} options={[{ value: 'all', text: 'All difficulties' }, ...[1, 2, 3, 4].map(n => ({ value: String(n), text: `Difficulty ${n}` }))]} onChange={event => setDifficulty(event.target.value)} /></EuiFormRow>
            <EuiFormRow label='Category'><EuiSelect value={category} options={[{ value: 'all', text: 'All categories' }, ...categories.map(value => ({ value, text: value.replace(/_/g, ' ') }))]} onChange={event => setCategory(event.target.value)} /></EuiFormRow>
            <ul aria-label='Training scenarios'>{visible.map(s => <li key={s.id}>
              <EuiButton size='s' fill={selected?.id === s.id} onClick={() => selectScenario(s)}>{s.title}</EuiButton>{' '}
              <EuiBadge>Level {s.difficulty}</EuiBadge>{' '}{completed.includes(s.id) && <EuiBadge color='success'>Completed</EuiBadge>}
            </li>)}</ul>
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem grow={3}>
          {selected && <>
            <EuiPanel>
              <EuiTitle size='m'><h2>{selected.title}</h2></EuiTitle>
              <EuiText size='s'><p>{selected.category.replace(/_/g, ' ')} · Difficulty {selected.difficulty}</p></EuiText>
              <EuiTitle size='s'><h3>Wazuh alert evidence</h3></EuiTitle>
              <EuiCodeBlock language='json' isCopyable>{JSON.stringify(selected.alert, null, 2)}</EuiCodeBlock>
              <EuiSpacer size='m' />
              <EuiTitle size='s'><h3>Related log lines</h3></EuiTitle>
              {selected.evidence.log_lines.map((line, index) => <EuiText key={index}><p>{line}</p></EuiText>)}
              <EuiTitle size='s'><h3>Context notes</h3></EuiTitle>
              {selected.evidence.context_notes.map((note, index) => <EuiText key={index}><p>{note}</p></EuiText>)}
              <EuiButton onClick={() => void requestHint()} isDisabled={hintLevel >= 3}>Hint (free) {hintLevel}/3</EuiButton>
              {hints.map((hint, index) => <EuiText key={index}><p>Hint {index + 1}: {hint}</p></EuiText>)}
            </EuiPanel>
            {!result && <EuiPanel>
              <EuiTitle size='m'><h2>Your assessment</h2></EuiTitle>
              <EuiFormRow label='Verdict'><EuiSelect value={verdict} options={[{ value: 'true_positive', text: 'True positive' }, { value: 'false_positive', text: 'False positive' }, { value: 'benign', text: 'Benign' }]} onChange={event => setVerdict(event.target.value)} /></EuiFormRow>
              <EuiSwitch label='Escalate this alert' checked={escalate} onChange={event => setEscalate(event.target.checked)} />
              <EuiFormRow label='Search MITRE techniques'><EuiFieldSearch value={techniqueSearch} onChange={event => setTechniqueSearch(event.target.value)} placeholder='Search technique ID or name' /></EuiFormRow>
              {techniques.slice(0, 10).map(technique => <EuiButton key={technique.id} size='s' onClick={() => setMitreIds(ids => ids.includes(technique.id) ? ids : [...ids, technique.id])}>{technique.id} · {technique.name}</EuiButton>)}
              <EuiText size='s'><p>Selected: {mitreIds.join(', ') || 'None'}</p></EuiText>
              <EuiFormRow label='Short investigation report'><EuiTextArea value={report} onChange={event => setReport(event.target.value)} rows={8} placeholder={'Summary:\nEvidence:\nActions taken:\nUnknowns / not yet verified:'} /></EuiFormRow>
              <EuiButton fill onClick={() => void submitAttempt()}>Submit assessment</EuiButton>
            </EuiPanel>}
            {result && <EuiPanel>
              <EuiTitle size='m'><h2>Your score: {result.score.total}/{result.score.maximum}</h2></EuiTitle>
              <EuiText><p>Verdict: {result.score.verdict.points}/40 · Escalation: {result.score.escalation.points}/20 · MITRE: {result.score.mitre.points}/20 · Report: {result.score.report.points}/20</p></EuiText>
              <EuiText><p>Verdict {result.score.verdict.correct === null ? 'not graded: review needed' : result.score.verdict.correct ? 'correct' : 'review the expected verdict'}; escalation {result.score.escalation.correct === null ? 'not graded' : result.score.escalation.correct ? 'correct' : 'needs review'}; invalid MITRE IDs: {result.score.mitre.invalid.join(', ') || 'none'}.</p></EuiText>
              <EuiTitle size='s'><h3>Coaching explanation</h3></EuiTitle><EuiText><p>{result.explanation}</p></EuiText>
              <EuiButton fill onClick={() => { const next = visible.find(item => item.id !== selected.id && !completed.includes(item.id)); if (next) selectScenario(next); else { setSelected(undefined); setResult(undefined); } }}>Next scenario</EuiButton>
            </EuiPanel>}
          </>}
        </EuiFlexItem>
      </EuiFlexGroup>
    </EuiPageContent></EuiPageBody></EuiPage>
  );
};

export default TrainingPage;
