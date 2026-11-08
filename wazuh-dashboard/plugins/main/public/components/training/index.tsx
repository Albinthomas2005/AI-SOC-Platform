import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiCallOut,
  EuiCodeBlock,
  EuiFieldSearch,
  EuiFieldText,
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
  const [progress, setProgress] = useState<any>();
  const [hintLevel, setHintLevel] = useState(0);
  const [hints, setHints] = useState<string[]>([]);
  const [verdict, setVerdict] = useState('true_positive');
  const [escalate, setEscalate] = useState(true);
  const [report, setReport] = useState('');
  const [techniqueSearch, setTechniqueSearch] = useState('');
  const [manualTechnique, setManualTechnique] = useState('');
  const [techniques, setTechniques] = useState<Technique[]>([]);
  const [mitreIds, setMitreIds] = useState<string[]>([]);
  const [result, setResult] = useState<any>();
  const [coaching, setCoaching] = useState<any>();
  const [coachingLoading, setCoachingLoading] = useState(false);
  const [error, setError] = useState(false);
  const [startedAt, setStartedAt] = useState(Date.now());
  const [shift, setShift] = useState<any>();
  const [shiftIndex, setShiftIndex] = useState(0);
  const [shiftRemaining, setShiftRemaining] = useState(0);
  const [shiftSummary, setShiftSummary] = useState<any>();
  const [completedShiftId, setCompletedShiftId] = useState<string>();
  const [handoverNote, setHandoverNote] = useState('');
  const [handoverCoaching, setHandoverCoaching] = useState<any>();
  const [handoverLoading, setHandoverLoading] = useState(false);
  const finishingShift = useRef(false);

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
    WzRequest.genericReq('GET', '/api/training/progress', undefined, { shouldRetry: false, checkCurrentApiIsUp: false })
      .then((response: any) => {
        if (!active || !response?.data?.ok) return;
        const summary = response.data.progress;
        setProgress(summary);
        setCompleted((summary.attempts || []).map((attempt: any) => attempt.scenario_id));
      }).catch(() => {});
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

  const finishShift = useCallback(async (shiftId = shift?.shift_id) => {
    if (!shiftId || finishingShift.current) return;
    finishingShift.current = true;
    try {
      const response: any = await WzRequest.genericReq('POST', `/api/training/shifts/${shiftId}/complete`, {}, { shouldRetry: false, checkCurrentApiIsUp: false });
      if (!response?.data?.ok) throw new Error('Invalid shift summary');
      setShiftSummary(response.data.summary);
      setCompletedShiftId(shiftId);
      setShift(undefined);
      setSelected(undefined);
      setHandoverNote('');
      setHandoverCoaching(undefined);
    } catch { setError(true); }
    finally { finishingShift.current = false; }
  }, [shift]);

  useEffect(() => {
    if (!shift) return undefined;
    const tick = () => {
      const remaining = Math.max(0, Math.ceil((Date.parse(shift.deadline_at) - Date.now()) / 1000));
      setShiftRemaining(remaining);
      if (remaining === 0) void finishShift(shift.shift_id);
    };
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [shift, finishShift]);

  const selectScenario = (scenario: Scenario) => {
    setSelected(scenario);
    setResult(undefined);
    setCoaching(undefined);
    setHints([]);
    setHintLevel(0);
    setVerdict('true_positive');
    setEscalate(true);
    setMitreIds([]);
    setReport('');
    setStartedAt(Date.now());
  };

  const requestHint = async () => {
    if (!selected || shift) return;
    try {
      const next = hintLevel + 1;
      const response: any = await WzRequest.genericReq('GET', `/api/training/scenarios/${encodeURIComponent(selected.id)}/hints?level=${next}`, undefined, { shouldRetry: false, checkCurrentApiIsUp: false });
      setHints(response?.data?.hints || []);
      setHintLevel(next);
    } catch { setError(true); }
  };

  const startShift = async () => {
    setError(false);
    setShiftSummary(undefined);
    setCompletedShiftId(undefined);
    setResult(undefined);
    try {
      const response: any = await WzRequest.genericReq('POST', '/api/training/shifts', {}, { shouldRetry: false, checkCurrentApiIsUp: false });
      if (!response?.data?.ok || !Array.isArray(response.data.scenarios) || response.data.scenarios.length !== 8) throw new Error('Invalid shift response');
      setShift(response.data);
      setShiftIndex(0);
      setShiftRemaining(response.data.duration_seconds);
      selectScenario(response.data.scenarios[0]);
    } catch { setError(true); }
  };

  const recordShiftResponse = async () => {
    if (!shift || !selected) return;
    setError(false);
    try {
      const response: any = await WzRequest.genericReq('POST', `/api/training/shifts/${shift.shift_id}/responses`, {
        scenario_id: selected.id, verdict, escalate, mitre_ids: mitreIds,
        report_text: report, time_spent: Math.max(0, Math.floor((Date.now() - startedAt) / 1000)),
      }, { shouldRetry: false, checkCurrentApiIsUp: false });
      if (!response?.data?.ok) throw new Error('Shift response was not recorded');
      const nextIndex = shiftIndex + 1;
      if (nextIndex >= shift.scenarios.length) await finishShift(shift.shift_id);
      else {
        setShiftIndex(nextIndex);
        selectScenario(shift.scenarios[nextIndex]);
      }
    } catch { setError(true); }
  };

  const submitHandover = async () => {
    if (!shiftSummary || !completedShiftId) return;
    setHandoverLoading(true);
    try {
      const response: any = await WzRequest.genericReq('POST', `/api/training/shifts/${completedShiftId}/handover`, { note: handoverNote }, { shouldRetry: false, checkCurrentApiIsUp: false });
      if (!response?.data?.ok) throw new Error('Handover coaching unavailable');
      setHandoverCoaching(response.data.coaching);
    } catch { setError(true); }
    finally { setHandoverLoading(false); }
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
      setCoachingLoading(true);
      try {
        const coached: any = await WzRequest.genericReq('POST', `/api/training/attempts/${response.data.attempt_id}/coaching`, {}, { shouldRetry: false, checkCurrentApiIsUp: false });
        if (coached?.data?.ok) setCoaching(coached.data.coaching);
      } catch {
        setError(true);
      } finally {
        setCoachingLoading(false);
      }
    } catch { setError(true); }
  };

  return (
    <EuiPage paddingSize='l'><EuiPageBody><EuiPageContent paddingSize='l'>
      <EuiTitle size='l'><h1>Analyst Training</h1></EuiTitle>
      <EuiText size='s'><p>Work from the supplied synthetic evidence. Unverified facts are not yet verified.</p></EuiText>
      <EuiButton fill onClick={() => void startShift()} isDisabled={!!shift}>Start 8-case timed shift</EuiButton>
      {shift && <EuiCallOut title={`Shift in progress · ${Math.floor(shiftRemaining / 60)}:${String(shiftRemaining % 60).padStart(2, '0')} remaining`}><p>Case {shiftIndex + 1} of 8 · Hints are disabled during shifts.</p></EuiCallOut>}
      <EuiSpacer />
      {error && <EuiCallOut color='danger' title='Training service is unavailable. Try again.' />}
      {shiftSummary && <EuiPanel>
        <EuiTitle size='m'><h2>Shift summary · {Math.round(shiftSummary.average_score)}% ({shiftSummary.total_points}/{shiftSummary.maximum_points})</h2></EuiTitle>
        <EuiText><p>Cases completed: {shiftSummary.completed_count}/8{shiftSummary.timed_out ? ' · Timer expired' : ''}</p></EuiText>
        <ul>{shiftSummary.cases.map((item: any) => <li key={item.scenario_id}>{item.title} · {item.score}/100{item.missing ? ' · not submitted' : ''}</li>)}</ul>
        <EuiFormRow label='Shift handover note'><EuiTextArea value={handoverNote} onChange={event => setHandoverNote(event.target.value)} rows={5} placeholder='Status, key evidence, unresolved items, and next owner/actions' /></EuiFormRow>
        <EuiButton onClick={() => void submitHandover()} isLoading={handoverLoading} isDisabled={!handoverNote.trim()}>Get handover coaching</EuiButton>
        {handoverCoaching && <EuiText><p><strong>Clarity:</strong> {handoverCoaching.clarity_feedback}</p><p><strong>Completeness:</strong> {handoverCoaching.completeness_feedback}</p><p><strong>Practise:</strong> {handoverCoaching.next_shift_practice}</p></EuiText>}
      </EuiPanel>}
      <EuiFlexGroup gutterSize='l' responsive>
        <EuiFlexItem grow={1}>
          <EuiPanel>
            <EuiTitle size='s'><h2>Scenario queue</h2></EuiTitle>
            <EuiFormRow label='Difficulty'><EuiSelect disabled={!!shift} value={difficulty} options={[{ value: 'all', text: 'All difficulties' }, ...[1, 2, 3, 4].map(n => ({ value: String(n), text: `Difficulty ${n}` }))]} onChange={event => setDifficulty(event.target.value)} /></EuiFormRow>
            <EuiFormRow label='Category'><EuiSelect disabled={!!shift} value={category} options={[{ value: 'all', text: 'All categories' }, ...categories.map(value => ({ value, text: value.replace(/_/g, ' ') }))]} onChange={event => setCategory(event.target.value)} /></EuiFormRow>
            <ul aria-label='Training scenarios'>{visible.map(s => <li key={s.id}>
              <EuiButton size='s' fill={selected?.id === s.id} isDisabled={!!shift} onClick={() => selectScenario(s)}>{s.title}</EuiButton>{' '}
              <EuiBadge>Level {s.difficulty}</EuiBadge>{' '}{completed.includes(s.id) && <EuiBadge color='success'>Completed</EuiBadge>}{' '}{s.status.includes('draft') && <EuiBadge color='warning'>Draft · needs review</EuiBadge>}
            </li>)}</ul>
            <EuiSpacer size='m' />
            <EuiTitle size='s'><h3>Your progress</h3></EuiTitle>
            <EuiText size='s'><p>Attempts: {progress?.attempt_count ?? 0} · Verdict accuracy: {progress?.verdict_accuracy === null || progress?.verdict_accuracy === undefined ? '—' : `${Math.round(progress.verdict_accuracy * 100)}%`} · Average time: {progress?.time_per_case?.average_seconds === null || progress?.time_per_case?.average_seconds === undefined ? '—' : `${Math.round(progress.time_per_case.average_seconds)} sec`}</p></EuiText>
            {progress?.per_category_accuracy && Object.entries(progress.per_category_accuracy).map(([name, stats]: [string, any]) => <EuiText size='s' key={name}><p>{name.replace(/_/g, ' ')}: {stats.accuracy === null ? 'not graded' : `${Math.round(stats.accuracy * 100)}%`} ({stats.attempts} attempts)</p></EuiText>)}
            {!!progress?.common_mistakes?.length && <EuiText size='s'><p>Common mistakes: {progress.common_mistakes.map((item: any) => `${item.mistake.replace(/_/g, ' ')} (${item.count})`).join(', ')}</p></EuiText>}
            {!!progress?.attempts?.length && <><EuiTitle size='xs'><h4>Attempt history</h4></EuiTitle><ul>{progress.attempts.slice(0, 8).map((attempt: any) => <li key={attempt.attempt_id}>{attempt.title} · {attempt.score}/100 · {attempt.time_spent}s</li>)}</ul></>}
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
              {!shift && <><EuiButton onClick={() => void requestHint()} isDisabled={hintLevel >= 3}>Hint (free) {hintLevel}/3</EuiButton>
              {hints.map((hint, index) => <EuiText key={index}><p>Hint {index + 1}: {hint}</p></EuiText>)}</>}
            </EuiPanel>
            {!result && <EuiPanel>
              <EuiTitle size='m'><h2>Your assessment</h2></EuiTitle>
              <EuiFormRow label='Verdict'><EuiSelect value={verdict} options={[{ value: 'true_positive', text: 'True positive' }, { value: 'false_positive', text: 'False positive' }, { value: 'benign', text: 'Benign' }]} onChange={event => setVerdict(event.target.value)} /></EuiFormRow>
              <EuiSwitch label='Escalate this alert' checked={escalate} onChange={event => setEscalate(event.target.checked)} />
              <EuiFormRow label='Search MITRE techniques'><EuiFieldSearch value={techniqueSearch} onChange={event => setTechniqueSearch(event.target.value)} placeholder='Search technique ID or name' /></EuiFormRow>
              {techniques.slice(0, 10).map(technique => <EuiButton key={technique.id} size='s' onClick={() => setMitreIds(ids => ids.includes(technique.id) ? ids : [...ids, technique.id])}>{technique.id} · {technique.name}</EuiButton>)}
              <EuiFormRow label='Add a technique ID if the local catalog is unavailable'><EuiFlexGroup gutterSize='s'><EuiFlexItem><EuiFieldText value={manualTechnique} onChange={event => setManualTechnique(event.target.value)} placeholder='T1110.001' /></EuiFlexItem><EuiFlexItem grow={false}><EuiButton onClick={() => { if (manualTechnique.trim()) setMitreIds(ids => ids.includes(manualTechnique.trim()) ? ids : [...ids, manualTechnique.trim()]); setManualTechnique(''); }}>Add ID</EuiButton></EuiFlexItem></EuiFlexGroup></EuiFormRow>
              <EuiText size='s'><p>Selected: {mitreIds.join(', ') || 'None'}</p></EuiText>
              <EuiFormRow label='Short investigation report'><EuiTextArea value={report} onChange={event => setReport(event.target.value)} rows={8} placeholder={'Summary:\nEvidence:\nActions taken:\nUnknowns / not yet verified:'} /></EuiFormRow>
              <EuiButton fill onClick={() => void (shift ? recordShiftResponse() : submitAttempt())}>{shift ? (shiftIndex === 7 ? 'Record and score shift' : 'Record decision and continue') : 'Submit assessment'}</EuiButton>
            </EuiPanel>}
            {result && <EuiPanel>
              <EuiTitle size='m'><h2>Your score: {result.score.total}/{result.score.maximum}</h2></EuiTitle>
              <EuiText><p>Verdict: {result.score.verdict.points}/40 · Escalation: {result.score.escalation.points}/20 · MITRE: {result.score.mitre.points}/20 · Report: {result.score.report.points}/20</p></EuiText>
              <EuiText><p>Verdict {result.score.verdict.correct === null ? 'not graded: review needed' : result.score.verdict.correct ? 'correct' : 'review the expected verdict'}; escalation {result.score.escalation.correct === null ? 'not graded' : result.score.escalation.correct ? 'correct' : 'needs review'}; invalid MITRE IDs: {result.score.mitre.invalid.join(', ') || 'none'}.</p></EuiText>
              <EuiTitle size='s'><h3>Coaching explanation</h3></EuiTitle><EuiText><p>{result.explanation}</p></EuiText>
              <EuiTitle size='s'><h3>Analyst vs AI vs expected</h3></EuiTitle>
              <EuiFlexGroup>
                <EuiFlexItem><EuiPanel><strong>Analyst</strong><p>{result.analyst.verdict} · {result.analyst.escalate ? 'escalate' : 'close'}</p><p>MITRE: {result.analyst.mitre_ids.join(', ') || 'none'}</p></EuiPanel></EuiFlexItem>
                <EuiFlexItem><EuiPanel><strong>AI assessment</strong><p>{result.ai ? `${result.ai.verdict} · ${result.ai.escalate ? 'escalate' : 'close'}` : 'AI assessment unavailable'}</p><p>MITRE: {result.ai?.mitre_ids?.join(', ') || 'none'}</p></EuiPanel></EuiFlexItem>
                <EuiFlexItem><EuiPanel><strong>Expected</strong><p>{result.expected.verdict || 'not yet reviewed'} · {result.expected.escalate === null ? 'not yet reviewed' : result.expected.escalate ? 'escalate' : 'close'}</p><p>MITRE: {result.expected.mitre_ids.join(', ') || 'not yet reviewed / none'}</p></EuiPanel></EuiFlexItem>
              </EuiFlexGroup>
              <EuiTitle size='s'><h3>Report coaching</h3></EuiTitle>
              {coachingLoading && <EuiText><p>Preparing coaching…</p></EuiText>}
              {coaching && <EuiText><p><strong>Good:</strong> {coaching.what_was_good}</p><p><strong>Missed:</strong> {coaching.what_was_missed}</p><p><strong>Practise:</strong> {coaching.one_thing_to_practise}</p></EuiText>}
              {!coachingLoading && !coaching && <EuiText><p>AI coaching is unavailable right now.</p></EuiText>}
              <EuiButton fill onClick={() => { const next = visible.find(item => item.id !== selected.id && !completed.includes(item.id)); if (next) selectScenario(next); else { setSelected(undefined); setResult(undefined); } }}>Next scenario</EuiButton>
            </EuiPanel>}
          </>}
        </EuiFlexItem>
      </EuiFlexGroup>
    </EuiPageContent></EuiPageBody></EuiPage>
  );
};

export default TrainingPage;
