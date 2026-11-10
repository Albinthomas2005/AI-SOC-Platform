import {
  OpenSearchDashboardsRequest,
  RequestHandlerContext,
  OpenSearchDashboardsResponseFactory,
} from 'src/core/server';
import { WAZUH_ALERTS_PREFIX } from '../../common/constants';
import { socAiUsername } from '../lib/soc-ai-identity';

type NeedleOptions = {
  headers: Record<string, string>;
  open_timeout: number;
  response_timeout: number;
  read_timeout: number;
};
type NeedleResponse = { statusCode?: number; body?: Record<string, any> };
type NeedleCall = (method: string, url: string, data: unknown, options: NeedleOptions) => Promise<NeedleResponse>;

// Needle does not ship TypeScript declarations.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const needle = require('needle') as NeedleCall;
const TIMEOUT_MS = 45000;
const ALERT_FIELDS = [
  '@timestamp', 'timestamp', 'rule.id', 'rule.level', 'rule.description',
  'rule.groups', 'rule.mitre.id', 'rule.mitre.tactic', 'rule.mitre.technique',
  'decoder.name', 'agent.id', 'data.srcip', 'data.dstip', 'data.srcport',
  'data.dstport', 'data.protocol', 'data.action', 'data.authentication_result',
  'data.win.system.eventID',
];

function validAlertRef(index: unknown, id: unknown, pattern: unknown): boolean {
  if (
    typeof index !== 'string' ||
    typeof id !== 'string' ||
    !id || Buffer.byteLength(id, 'utf8') > 512 ||
    !index.startsWith(WAZUH_ALERTS_PREFIX) ||
    !/^[a-z0-9][a-z0-9._-]*$/.test(index) ||
    typeof pattern !== 'string' ||
    !pattern.startsWith(WAZUH_ALERTS_PREFIX)
  ) return false;
  const escaped = pattern.split('*').map(part => part.replace(/[|\\{}()[\]^$+?.]/g, '\\$&')).join('.*');
  return new RegExp(`^${escaped}$`).test(index);
}

function backendErrorMessage(body: Record<string, any> | undefined, token: string, statusCode?: number) {
  const supplied = typeof body?.error === 'string'
    ? body.error
    : typeof body?.message === 'string' ? body.message : '';
  if (!supplied.trim()) return statusCode ? `Backend returned HTTP ${statusCode}` : 'Invalid backend response';
  return supplied
    .replace(token ? new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g') : /$^/, '[redacted]')
    .replace(/Bearer\s+\S+/gi, 'Bearer [redacted]');
}

function errorBody(message: string) {
  return { ok: false, error: message, message };
}

function backendUrl(): string | undefined {
  const explicit = process.env.SOC_AI_BASE_URL?.trim();
  const host = process.env.SOC_AI_HOST?.trim();
  const port = process.env.SOC_AI_PORT?.trim();
  const raw = explicit || `http://${host || '127.0.0.1'}:${port || '5000'}`;
  try {
    const parsed = new URL(raw);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname !== '/' && parsed.pathname !== '')) return undefined;
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return undefined;
  }
}

export class WazuhPhaseCtrl {
  private async currentUsername(context: RequestHandlerContext, request: OpenSearchDashboardsRequest): Promise<string | undefined> {
    try {
      const user = await context.wazuh.security.getCurrentUser(request, context);
      return typeof user?.username === 'string' ? socAiUsername(user.username) : undefined;
    } catch {
      return undefined;
    }
  }

  private async backend(
    method: 'get' | 'post' | 'delete',
    path: string,
    body: unknown,
    username: string,
    response: OpenSearchDashboardsResponseFactory,
  ) {
    const token = process.env.SOC_AI_INTERNAL_TOKEN?.trim();
    if (!token) return response.custom({ statusCode: 503, body: errorBody('backend token not configured') });
    const baseUrl = backendUrl();
    if (!baseUrl) return response.custom({ statusCode: 503, body: errorBody('backend URL not configured') });
    try {
      const upstream = await needle(method, `${baseUrl}${path}`, body, {
        json: true,
        headers: {
          Authorization: `Bearer ${token}`,
          'X-SOC-User': username,
        },
        // eslint-disable-next-line camelcase
        open_timeout: TIMEOUT_MS,
        // eslint-disable-next-line camelcase
        response_timeout: TIMEOUT_MS,
        // eslint-disable-next-line camelcase
        read_timeout: TIMEOUT_MS,
      });
      if (
        typeof upstream.statusCode !== 'number' ||
        upstream.statusCode < 200 || upstream.statusCode >= 300 ||
        upstream.body?.ok !== true
      ) {
        const statusCode = typeof upstream.statusCode === 'number'
          ? (upstream.statusCode < 200 || upstream.statusCode >= 300 ? upstream.statusCode : 502)
          : 502;
        return response.custom({ statusCode, body: errorBody(backendErrorMessage(upstream.body, token, upstream.statusCode)) });
      }
      return response.ok({ body: upstream.body });
    } catch {
      return response.custom({ statusCode: 503, body: errorBody('backend unreachable') });
    }
  }

  private async selectedAlerts(
    context: RequestHandlerContext,
    request: OpenSearchDashboardsRequest,
    response: OpenSearchDashboardsResponseFactory,
  ): Promise<{ alerts?: Array<Record<string, unknown>>; error?: any }> {
    const references = (request.body || {}).alert_refs;
    if (!Array.isArray(references) || !references.length || references.length > 50) {
      return { error: response.custom({ statusCode: 400, body: errorBody('Provide 1-50 alert references') }) };
    }
    let pattern: unknown;
    try {
      pattern = await context.wazuh_core.configuration.getSettingValue('pattern');
    } catch {
      return { error: response.custom({ statusCode: 503, body: errorBody('Alert search is unavailable') }) };
    }
    const alerts = [];
    for (const reference of references) {
      if (!reference || !validAlertRef(reference.index, reference.id, pattern)) {
        return { error: response.custom({ statusCode: 400, body: errorBody('Invalid Wazuh alert reference') }) };
      }
      try {
        const result = await context.core.opensearch.client.asCurrentUser.search({
          index: reference.index,
          body: {
            size: 1,
            // OpenSearch uses this API field name.
            // eslint-disable-next-line camelcase
            track_total_hits: false,
            query: { ids: { values: [reference.id] } },
            _source: ALERT_FIELDS,
          },
        });
        const source = result?.body?.hits?.hits?.[0]?._source;
        if (source) alerts.push({ _id: reference.id, ...source });
      } catch (error) {
        const status = (error as any)?.meta?.statusCode ?? (error as any)?.statusCode;
        return { error: response.custom({
          statusCode: status === 403 ? 403 : 503,
          body: errorBody(status === 403 ? 'Access to this alert is denied' : 'Alert search is unavailable'),
        }) };
      }
    }
    return { alerts };
  }

  async correlate(context: RequestHandlerContext, request: OpenSearchDashboardsRequest, response: OpenSearchDashboardsResponseFactory) {
    const username = await this.currentUsername(context, request);
    if (!username) return response.custom({ statusCode: 401, body: errorBody('Authentication required') });
    const selected = await this.selectedAlerts(context, request, response);
    if (selected.error) return selected.error;
    return this.backend('post', '/api/correlations', { alerts: selected.alerts || [] }, username, response);
  }

  async lookupThreatIntel(context: RequestHandlerContext, request: OpenSearchDashboardsRequest, response: OpenSearchDashboardsResponseFactory) {
    const username = await this.currentUsername(context, request);
    if (!username) return response.custom({ statusCode: 401, body: errorBody('Authentication required') });
    const selected = await this.selectedAlerts(context, request, response);
    if (selected.error) return selected.error;
    const alert = selected.alerts?.[0];
    if (!alert) return response.custom({ statusCode: 404, body: errorBody('Alert is unavailable') });
    return this.backend('post', '/api/threat-intel/lookup', { alert }, username, response);
  }

  async filterLabAlerts(context: RequestHandlerContext, request: OpenSearchDashboardsRequest, response: OpenSearchDashboardsResponseFactory) {
    if (!(await this.currentUsername(context, request))) return response.custom({ statusCode: 401, body: errorBody('Authentication required') });
    const references = (request.body || {}).alert_refs;
    if (!Array.isArray(references) || references.length > 50) return response.custom({ statusCode: 400, body: errorBody('Provide up to 50 alert references') });
    let pattern: unknown;
    try { pattern = await context.wazuh_core.configuration.getSettingValue('pattern'); }
    catch { return response.custom({ statusCode: 503, body: errorBody('Alert search is unavailable') }); }
    const filtered = [];
    for (const reference of references) {
      if (!reference || !validAlertRef(reference.index, reference.id, pattern)) return response.custom({ statusCode: 400, body: errorBody('Invalid Wazuh alert reference') });
      try {
        const result = await context.core.opensearch.client.asCurrentUser.search({
          index: reference.index,
          body: { size: 1, query: { ids: { values: [reference.id] } }, _source: ['full_log'] },
        });
        const hit = result?.body?.hits?.hits?.[0];
        if (typeof hit?._source?.full_log === 'string' && hit._source.full_log.includes('SOCLAB-INJECT')) filtered.push(reference);
      } catch { return response.custom({ statusCode: 503, body: errorBody('Alert search is unavailable') }); }
    }
    return response.ok({ body: { ok: true, alert_refs: filtered, hidden_count: references.length - filtered.length } });
  }

  async proxy(context: RequestHandlerContext, request: OpenSearchDashboardsRequest, response: OpenSearchDashboardsResponseFactory, method: 'get' | 'post' | 'delete', path: string, body?: unknown) {
    const username = await this.currentUsername(context, request);
    if (!username) return response.custom({ statusCode: 401, body: errorBody('Authentication required') });
    let target = path;
    if (method === 'get' && request.query && Object.keys(request.query).length) {
      target += `?${new URLSearchParams(request.query as Record<string, string>).toString()}`;
    }
    return this.backend(method, target, body === undefined ? (request.body || {}) : body, username, response);
  }
}
