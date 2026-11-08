import React, { useState } from 'react';
import { WzRequest } from '../../react-services/wz-request';

const ALLOWED_FIELDS = [
  'rule.id',
  'rule.description',
  'rule.level',
  'rule.groups',
  'rule.mitre.id',
  'rule.mitre.tactic',
  'agent.name',
  'data.srcip',
  'data.srcuser',
  'data.dstuser',
  'location',
];

type AlertObject = Record<string, any>;
type DiscoverHit = { _id?: string; _source?: AlertObject };

const hasValue = (value: unknown) =>
  (typeof value === 'string' && value.trim().length > 0) ||
  (typeof value === 'number' && Number.isFinite(value)) ||
  (Array.isArray(value) && value.length > 0);

export const minimizeHitSource = (source: AlertObject = {}) => {
  const minimized: AlertObject = {};
  ALLOWED_FIELDS.forEach(path => {
    let value = path.split('.').reduce<any>((current, key) => current?.[key], source);
    if (Array.isArray(value)) {
      value = value
        .filter(item => typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean')
        .slice(0, 50);
    }
    if (typeof value === 'string') value = value.slice(0, 4096);
    if (!hasValue(value)) return;
    const parts = path.split('.');
    let target = minimized;
    parts.slice(0, -1).forEach(part => {
      target[part] = target[part] || {};
      target = target[part];
    });
    target[parts[parts.length - 1]] = value;
  });
  return minimized;
};

const missingTokenMessage =
  'The AI assistant is not configured. Ask an administrator to configure the backend token.';

export const DiscoverAIAnalyst = ({ hit }: { hit: DiscoverHit }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [answer, setAnswer] = useState('');
  const [citations, setCitations] = useState<Array<{ type: string; id: string }>>([]);

  const analyze = async () => {
    const id = typeof hit?._id === 'string' ? hit._id : '';
    const alert = minimizeHitSource(hit?._source);
    if (!id || !Object.keys(alert).length) {
      setError('This document has no supported alert fields to analyze.');
      return;
    }
    setLoading(true);
    setError('');
    setAnswer('');
    setCitations([]);
    try {
      const response = await WzRequest.genericReq(
        'POST',
        '/api/phase/assistant/chat',
        {
          question: 'Analyze this alert using only its supplied fields and cite the supplied alert.',
          evidence: [{ type: 'alert', id }],
          alert,
        },
        { shouldRetry: false, checkCurrentApiIsUp: false },
      );
      const result = response?.data;
      if (result?.ok !== true || typeof result.answer !== 'string' || !result.answer.trim()) {
        throw new Error('Invalid assistant response');
      }
      if (
        !Array.isArray(result.citations) ||
        !result.citations.some((citation: any) => citation?.type === 'alert' && citation.id === id)
      ) {
        throw new Error('Assistant response did not cite this alert');
      }
      setAnswer(result.answer);
    setCitations(result.citations);
    } catch (requestError: any) {
      setError(
        [401, 503].includes(requestError?.response?.status ?? requestError?.status)
          ? missingTokenMessage
          : 'The alert could not be analyzed. Check the backend connection and try again.',
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <section aria-label='AI Analyst'>
      <button type='button' onClick={() => void analyze()} disabled={loading}>
        {loading ? 'Analyzing…' : 'Analyze this alert'}
      </button>
      {loading && <p role='status'>Analyzing alert…</p>}
      {error && <p role='alert'>{error}</p>}
      {answer && (
        <div>
          <h3>Analysis</h3>
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{answer}</pre>
          {citations.length > 0 && (
            <p>Cited evidence: {citations.map(item => `[${item.type}:${item.id}]`).join(', ')}</p>
          )}
        </div>
      )}
    </section>
  );
};
