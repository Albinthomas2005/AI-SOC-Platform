import {
  OpenSearchDashboardsRequest,
  RequestHandlerContext,
  OpenSearchDashboardsResponseFactory,
} from 'src/core/server';
import { WAZUH_ALERTS_PREFIX } from '../../common/constants';

type NeedleOptions = {
  json: boolean;
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
const BASE_URL = `http://${process.env.SOC_AI_HOST || '127.0.0.1'}:${process.env.SOC_AI_PORT || '5000'}`;
const TOKEN = () => process.env.SOC_AI_INTERNAL_TOKEN;
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

export class WazuhPhaseCtrl {
  private async currentUsername(context: RequestHandlerContext, request: OpenSearchDashboardsRequest): Promise<string | undefined> {
    try {
      const user = await context.wazuh.security.getCurrentUser(request, context);
      return typeof user?.username === 'string' ? user.username : undefined;
    } catch {
      return undefined;
    }
  }

  private async backend(
    method: 'get' | 'post',
    path: string,
    body: unknown,
    username: string,
    response: OpenSearchDashboardsResponseFactory,
  ) {
    const token = TOKEN();
    if (!token) return response.custom({ statusCode: 503, body: { ok: false, error: 'SOC AI service is unavailable' } });
    try {
      const upstream = await needle(method, `${BASE_URL}${path}`, body, {
        json: true,
        headers: { Authorization: `Bearer ${token}`, 'X-SOC-User': username },
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
        return response.custom({
          statusCode: upstream.statusCode && upstream.statusCode >= 400 && upstream.statusCode < 500 ? upstream.statusCode : 503,
          body: upstream.body?.ok === false ? upstream.body : { ok: false, error: 'SOC AI service is unavailable' },
        });
      }
      return response.ok({ body: upstream.body });
    } catch {
      return response.custom({ statusCode: 503, body: { ok: false, error: 'SOC AI service is unavailable' } });
    }
  }

  private async selectedAlerts(
    context: RequestHandlerContext,
    request: OpenSearchDashboardsRequest,
    response: OpenSearchDashboardsResponseFactory,
  ): Promise<{ alerts?: Array<Record<string, unknown>>; error?: any }> {
    const references = (request.body || {}).alert_refs;
    if (!Array.isArray(references) || !references.length || references.length > 50) {
      return { error: response.custom({ statusCode: 400, body: { ok: false, error: 'Provide 1-50 alert references' } }) };
    }
    let pattern: unknown;
    try {
      pattern = await context.wazuh_core.configuration.getSettingValue('pattern');
    } catch {
      return { error: response.custom({ statusCode: 503, body: { ok: false, error: 'Alert search is unavailable' } }) };
    }
    const alerts = [];
    for (const reference of references) {
      if (!reference || !validAlertRef(reference.index, reference.id, pattern)) {
        return { error: response.custom({ statusCode: 400, body: { ok: false, error: 'Invalid Wazuh alert reference' } }) };
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
          body: { ok: false, error: status === 403 ? 'Access to this alert is denied' : 'Alert search is unavailable' },
        }) };
      }
    }
    return { alerts };
  }

  async correlate(context: RequestHandlerContext, request: OpenSearchDashboardsRequest, response: OpenSearchDashboardsResponseFactory) {
    const username = await this.currentUsername(context, request);
    if (!username) return response.custom({ statusCode: 401, body: { ok: false, error: 'Authentication required' } });
    const selected = await this.selectedAlerts(context, request, response);
    if (selected.error) return selected.error;
    return this.backend('post', '/api/correlations', { alerts: selected.alerts || [] }, username, response);
  }

  async lookupThreatIntel(context: RequestHandlerContext, request: OpenSearchDashboardsRequest, response: OpenSearchDashboardsResponseFactory) {
    const username = await this.currentUsername(context, request);
    if (!username) return response.custom({ statusCode: 401, body: { ok: false, error: 'Authentication required' } });
    const selected = await this.selectedAlerts(context, request, response);
    if (selected.error) return selected.error;
    const alert = selected.alerts?.[0];
    if (!alert) return response.custom({ statusCode: 404, body: { ok: false, error: 'Alert is unavailable' } });
    return this.backend('post', '/api/threat-intel/lookup', { alert }, username, response);
  }

  async proxy(context: RequestHandlerContext, request: OpenSearchDashboardsRequest, response: OpenSearchDashboardsResponseFactory, method: 'get' | 'post', path: string, body?: unknown) {
    const username = await this.currentUsername(context, request);
    if (!username) return response.custom({ statusCode: 401, body: { ok: false, error: 'Authentication required' } });
    let target = path;
    if (method === 'get' && request.query && Object.keys(request.query).length) {
      target += `?${new URLSearchParams(request.query as Record<string, string>).toString()}`;
    }
    return this.backend(method, target, body === undefined ? (request.body || {}) : body, username, response);
  }
}
