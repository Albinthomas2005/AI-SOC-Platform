export interface AiSocRecentAlert {
  id: string;
  index: string;
  timestamp?: string;
  title?: string;
  level?: number;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  host?: string;
}

export interface AiSocOverviewData {
  totalAlerts: number;
  totalRelation: 'eq' | 'gte';
  severity: Record<'low' | 'medium' | 'high' | 'critical', number>;
  recentAlerts: AiSocRecentAlert[];
  hiddenAlerts?: number;
}

export type AiSocQueryFailure = {
  kind: 'unauthorized' | 'permission-denied' | 'unavailable' | 'error';
  message: string;
};

const SEVERITY_FILTERS = {
  critical: { range: { 'rule.level': { gte: 15, lte: 16 } } },
  high: { range: { 'rule.level': { gte: 12, lte: 14 } } },
  medium: { range: { 'rule.level': { gte: 7, lte: 11 } } },
  low: { range: { 'rule.level': { gte: 0, lte: 6 } } },
};

export function buildAlertSeverityAgg() {
  return { severity: { filters: { filters: SEVERITY_FILTERS } } };
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function getField(source: unknown, path: string): unknown {
  let value: unknown = source;
  for (const part of path.split('.')) {
    const object = asObject(value);
    if (!object) return undefined;
    value = object[part];
  }
  return value;
}

function getText(source: unknown, paths: string[]): string | undefined {
  for (const path of paths) {
    const value = getField(source, path);
    if (typeof value === 'string' && value.trim()) return value;
  }
  return undefined;
}

function getCount(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0)
    return value;
  const count = asObject(value)?.value;
  return typeof count === 'number' && Number.isFinite(count) && count >= 0
    ? count
    : undefined;
}

function severityForLevel(value: unknown): AiSocRecentAlert['severity'] {
  const level =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim()
      ? Number(value)
      : NaN;
  if (!Number.isFinite(level)) return 'unknown';
  if (level >= 15) return 'critical';
  if (level >= 12) return 'high';
  if (level >= 7) return 'medium';
  if (level >= 0) return 'low';
  return 'unknown';
}

/** Map only fields present in the Wazuh 4 alert mappings and OpenSearch hit metadata. */
export function mapAiSocOverviewResponse(response: unknown): AiSocOverviewData {
  const root = asObject(response);
  const hits = asObject(root?.hits);
  const total = hits?.total;
  const totalAlerts = typeof total === 'number' ? total : getCount(total);
  const totalRelation = asObject(total)?.relation === 'gte' ? 'gte' : 'eq';
  const hitList = hits?.hits;
  const buckets = asObject(asObject(root?.aggregations)?.severity)?.buckets;
  if (totalAlerts === undefined || !Array.isArray(hitList) || !buckets) {
    throw new Error('Invalid Wazuh alert search response');
  }

  const severity = {} as AiSocOverviewData['severity'];
  for (const band of ['critical', 'high', 'medium', 'low'] as const) {
    const count = getCount(asObject(buckets[band])?.doc_count);
    if (count === undefined)
      throw new Error('Invalid Wazuh alert severity aggregation');
    severity[band] = count;
  }

  const recentAlerts = hitList.flatMap(hit => {
    const record = asObject(hit);
    const source = asObject(record?._source);
    if (
      !record ||
      typeof record._id !== 'string' ||
      typeof record._index !== 'string' ||
      !source
    )
      return [];
    const rawLevel = getField(source, 'rule.level');
    const level =
      typeof rawLevel === 'number'
        ? rawLevel
        : typeof rawLevel === 'string'
        ? Number(rawLevel)
        : undefined;
    return [
      {
        id: record._id,
        index: record._index,
        timestamp: getText(source, ['timestamp']),
        title: getText(source, ['rule.description']),
        level: Number.isFinite(level) ? level : undefined,
        severity: severityForLevel(rawLevel),
        host: getText(source, ['agent.name']),
      },
    ];
  });
  return { totalAlerts, totalRelation, severity, recentAlerts };
}

function getHttpStatus(error: unknown): number | undefined {
  const value = asObject(error);
  const response = asObject(value?.response);
  const body = asObject(value?.body);
  const meta = asObject(value?.meta);
  const status =
    value?.status ??
    value?.statusCode ??
    response?.status ??
    body?.statusCode ??
    meta?.statusCode;
  return typeof status === 'number' ? status : undefined;
}

/** Do not expose backend error bodies, stack traces, or other request details in the UI. */
export function classifyAiSocQueryFailure(error: unknown): AiSocQueryFailure {
  const status = getHttpStatus(error);
  if (status === 401)
    return {
      kind: 'unauthorized',
      message: 'Your session is no longer authorized. Sign in again and retry.',
    };
  if (status === 403)
    return {
      kind: 'permission-denied',
      message: "You don't have permission to view these Wazuh alerts.",
    };
  if (typeof error === 'string' && /alerts index pattern/i.test(error)) {
    return {
      kind: 'unavailable',
      message: 'The configured Wazuh alert index pattern is unavailable.',
    };
  }
  if (asObject(error)?.type === 'data_source_not_found') {
    return {
      kind: 'unavailable',
      message: 'The configured Wazuh alert index pattern is unavailable.',
    };
  }
  return {
    kind: 'error',
    message: 'Could not load Wazuh alerts. Check the service and try again.',
  };
}
