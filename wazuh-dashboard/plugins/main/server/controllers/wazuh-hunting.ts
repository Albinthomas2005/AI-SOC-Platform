import {
  OpenSearchDashboardsRequest,
  RequestHandlerContext,
  OpenSearchDashboardsResponseFactory,
} from 'src/core/server';

type NeedleOptions = {
  json: boolean;
  headers: Record<string, string>;
  open_timeout: number;
  response_timeout: number;
  read_timeout: number;
};

type NeedleResponse = {
  statusCode?: number;
  body?: Record<string, any>;
};

type NeedlePost = (
  method: string,
  url: string,
  data: unknown,
  options: NeedleOptions,
) => Promise<NeedleResponse>;

// Needle does not ship TypeScript declarations.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const needle = require('needle') as NeedlePost;

const AI_BASE_URL = `http://${process.env.SOC_AI_HOST || '127.0.0.1'}:${process.env.SOC_AI_PORT || '5000'}`;
const HUNT_PROPOSAL_URL = `${AI_BASE_URL}/api/hunts/proposals`;
const HUNT_RESULTS_URL = `${AI_BASE_URL}/api/hunts`;
const INTERNAL_TOKEN = () => process.env.SOC_AI_INTERNAL_TOKEN;
const HUNT_SIZE_LIMIT = 100;
const HUNT_TIMEOUT_MS = 45000;
const HUNT_INDEX = 'wazuh-alerts-4.x-*';
const HUNT_FIELDS = [
  '@timestamp', 'timestamp', 'rule.id', 'rule.level', 'rule.description',
  'rule.groups', 'rule.mitre.id', 'rule.mitre.tactic', 'rule.mitre.technique',
  'decoder.name', 'agent.id', 'data.srcip', 'data.dstip', 'data.srcport',
  'data.dstport', 'data.protocol', 'data.action', 'data.authentication_result',
];
const HUNT_QUERY_FIELDS = new Set([
  ...HUNT_FIELDS, 'agent.name', 'data.srcuser', 'data.dstuser',
]);
const HUNT_CLAUSES = new Set(['bool', 'match', 'term', 'range', 'exists']);

function isObject(value: unknown): value is Record<string, any> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function validateLeaf(operator: string, value: unknown): boolean {
  if (!isObject(value) || Object.keys(value).length !== 1) return false;
  if (operator === 'exists') {
    return value.field && HUNT_QUERY_FIELDS.has(value.field);
  }
  const field = Object.keys(value)[0];
  if (!HUNT_QUERY_FIELDS.has(field)) return false;
  const operand = value[field];
  if (operator === 'range') {
    return (
      ['@timestamp', 'timestamp', 'rule.level'].includes(field) &&
      isObject(operand) &&
      Object.keys(operand).length > 0 &&
      Object.keys(operand).every(key => ['gt', 'gte', 'lt', 'lte'].includes(key))
    );
  }
  return (
    (typeof operand === 'string' && operand.length <= 256) ||
    (typeof operand === 'number' && Number.isFinite(operand))
  );
}

function validateClause(value: unknown, depth = 0): boolean {
  if (!isObject(value) || Object.keys(value).length !== 1 || depth > 5) return false;
  const operator = Object.keys(value)[0];
  if (!HUNT_CLAUSES.has(operator)) return false;
  if (operator !== 'bool') return validateLeaf(operator, value[operator]);
  const clauses = value.bool;
  if (!isObject(clauses)) return false;
  const keys = Object.keys(clauses);
  if (!keys.length || keys.some(key => !['must', 'filter', 'should', 'must_not'].includes(key))) return false;
  return keys.every(key =>
    Array.isArray(clauses[key]) &&
    clauses[key].length > 0 &&
    clauses[key].length <= 10 &&
    clauses[key].every(item => validateClause(item, depth + 1)),
  );
}

function validateProposal(value: unknown): value is {
  query: { index: string; size: number; query: Record<string, unknown> };
} {
  if (!isObject(value) || !isObject(value.query)) return false;
  const query = value.query;
  return (
    query.index === HUNT_INDEX &&
    Number.isInteger(query.size) &&
    query.size >= 1 && query.size <= HUNT_SIZE_LIMIT &&
    validateClause(query.query)
  );
}

export class WazuhHuntingCtrl {
  async runHunt(
    context: RequestHandlerContext,
    request: OpenSearchDashboardsRequest,
    response: OpenSearchDashboardsResponseFactory,
  ) {
    let username: string;
    try {
      const currentUser = await context.wazuh.security.getCurrentUser(request, context);
      if (!currentUser || typeof currentUser.username !== 'string') throw new Error('unauthenticated');
      username = currentUser.username;
    } catch {
      return response.custom({ statusCode: 401, body: { ok: false, error: 'Authentication required' } });
    }

    const token = INTERNAL_TOKEN();
    const question = (request.body || {}).question;
    if (!token) return response.custom({ statusCode: 503, body: { ok: false, error: 'Hunting service is unavailable' } });
    if (typeof question !== 'string' || !question.trim() || question.length > 2000) {
      return response.custom({ statusCode: 400, body: { ok: false, error: 'A hunting question is required' } });
    }

    let proposalResponse: NeedleResponse;
    try {
      proposalResponse = await needle('post', HUNT_PROPOSAL_URL, { question: question.trim() }, {
        json: true,
        headers: { Authorization: `Bearer ${token}`, 'X-SOC-User': username },
        // eslint-disable-next-line camelcase
        open_timeout: HUNT_TIMEOUT_MS,
        // eslint-disable-next-line camelcase
        response_timeout: HUNT_TIMEOUT_MS,
        // eslint-disable-next-line camelcase
        read_timeout: HUNT_TIMEOUT_MS,
      });
    } catch {
      return response.custom({ statusCode: 503, body: { ok: false, error: 'Hunting proposal is unavailable' } });
    }
    const proposal = proposalResponse.body?.proposal;
    const huntId = proposalResponse.body?.hunt_id;
    if (
      proposalResponse.statusCode !== 201 ||
      proposalResponse.body?.ok !== true ||
      typeof huntId !== 'string' ||
      !/^[0-9a-f]{32}$/.test(huntId) ||
      !validateProposal(proposal)
    ) {
      return response.custom({ statusCode: 502, body: { ok: false, error: 'Hunting proposal failed validation' } });
    }

    let searchResult: any;
    try {
      // OpenSearch applies the signed-in user's index, document, and field permissions here.
      searchResult = await context.core.opensearch.client.asCurrentUser.search({
        index: proposal.query.index,
        body: {
          size: proposal.query.size,
          query: proposal.query.query,
          // OpenSearch uses this API field name.
          // eslint-disable-next-line camelcase
          track_total_hits: false,
          _source: HUNT_FIELDS,
        },
      });
    } catch (error) {
      const errorStatus = (error as any)?.meta?.statusCode ?? (error as any)?.statusCode;
      return response.custom({
        statusCode: errorStatus === 403 ? 403 : 503,
        body: { ok: false, error: errorStatus === 403 ? 'Access to hunt results is denied' : 'Hunt query could not be run' },
      });
    }

    const hits = searchResult?.body?.hits?.hits;
    const results = Array.isArray(hits)
      ? hits.slice(0, proposal.query.size).map((hit: any) => ({ _id: hit?._id, _source: hit?._source }))
      : [];
    try {
      const saved = await needle('post', `${HUNT_RESULTS_URL}/${huntId}/results`, { results }, {
        json: true,
        headers: { Authorization: `Bearer ${token}`, 'X-SOC-User': username },
        // eslint-disable-next-line camelcase
        open_timeout: HUNT_TIMEOUT_MS,
        // eslint-disable-next-line camelcase
        response_timeout: HUNT_TIMEOUT_MS,
        // eslint-disable-next-line camelcase
        read_timeout: HUNT_TIMEOUT_MS,
      });
      if (saved.statusCode !== 200 || saved.body?.ok !== true) {
        return response.custom({ statusCode: 503, body: { ok: false, error: 'Hunt report could not be saved' } });
      }
      return response.ok({
        body: {
          ok: true,
          hunt_id: huntId,
          proposal,
          interpretation: saved.body.interpretation,
          result_count: saved.body.result_count,
        },
      });
    } catch {
      return response.custom({ statusCode: 503, body: { ok: false, error: 'Hunt report could not be saved' } });
    }
  }
}
