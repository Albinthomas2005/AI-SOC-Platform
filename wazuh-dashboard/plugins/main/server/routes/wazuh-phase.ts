import { IRouter } from 'opensearch_dashboards/server';
import { schema } from '@osd/config-schema';
import { WazuhPhaseCtrl } from '../controllers';

export function WazuhPhaseRoutes(router: IRouter) {
  const ctrl = new WazuhPhaseCtrl();
  router.post({ path: '/api/phase/lab/filter', validate: false, options: { body: { maxBytes: 16 * 1024 } } }, (context, request, response) => ctrl.filterLabAlerts(context, request, response));
  router.get({ path: '/api/phase/lab/status', validate: false }, (context, request, response) => ctrl.proxy(context, request, response, 'get', '/api/lab/status'));
  router.get({ path: '/api/phase/lab/uploads', validate: false }, (context, request, response) => ctrl.proxy(context, request, response, 'get', '/api/lab/uploads'));
  router.get({ path: '/api/phase/lab/samples', validate: false }, (context, request, response) => ctrl.proxy(context, request, response, 'get', '/api/lab/samples'));
  router.post(
    {
      path: '/api/phase/lab/uploads',
      validate: false,
      options: { body: { maxBytes: 10 * 1024 * 1024, parse: false, output: 'data' } },
    },
    (context, request, response) => ctrl.uploadLab(context, request, response),
  );
  router.post({ path: '/api/phase/lab/samples/{name}', validate: { params: schema.object({ name: schema.string() }) } }, (context, request, response) => ctrl.proxy(context, request, response, 'post', `/api/lab/samples/${encodeURIComponent(request.params.name)}`));
  router.delete({ path: '/api/phase/lab/uploads/{id}', validate: { params: schema.object({ id: schema.string() }) } }, (context, request, response) => ctrl.proxy(context, request, response, 'delete', `/api/lab/uploads/${encodeURIComponent(request.params.id)}`));
  router.post(
    { path: '/api/phase/correlations/run', validate: false, options: { body: { maxBytes: 512 * 1024 } } },
    (context, request, response) => ctrl.correlate(context, request, response),
  );
  router.post(
    { path: '/api/phase/threat-intel/lookup', validate: false, options: { body: { maxBytes: 16 * 1024 } } },
    (context, request, response) => ctrl.lookupThreatIntel(context, request, response),
  );
  router.get(
    { path: '/api/phase/incidents', validate: false },
    (context, request, response) => ctrl.proxy(context, request, response, 'get', '/api/incidents'),
  );
  router.post(
    { path: '/api/phase/incidents', validate: false, options: { body: { maxBytes: 512 * 1024 } } },
    (context, request, response) => ctrl.proxy(context, request, response, 'post', '/api/incidents'),
  );
  router.get(
    { path: '/api/phase/incidents/{id}', validate: { params: schema.object({ id: schema.string() }) } },
    (context, request, response) => ctrl.proxy(context, request, response, 'get', `/api/incidents/${encodeURIComponent(request.params.id)}`),
  );
  router.get(
    { path: '/api/phase/incidents/{id}/report', validate: { params: schema.object({ id: schema.string() }) } },
    (context, request, response) => ctrl.proxy(context, request, response, 'get', `/api/incidents/${encodeURIComponent(request.params.id)}/report`),
  );
  router.post(
    { path: '/api/phase/incidents/{id}/status', validate: { params: schema.object({ id: schema.string() }), body: schema.object({ status: schema.string(), note: schema.maybe(schema.string()) }) } },
    (context, request, response) => ctrl.proxy(context, request, response, 'post', `/api/incidents/${encodeURIComponent(request.params.id)}/status`),
  );
  router.post(
    { path: '/api/phase/incidents/{id}/notes', validate: { params: schema.object({ id: schema.string() }), body: schema.object({ note: schema.string() }) } },
    (context, request, response) => ctrl.proxy(context, request, response, 'post', `/api/incidents/${encodeURIComponent(request.params.id)}/notes`),
  );
  router.get(
    { path: '/api/phase/admin/audit', validate: false },
    (context, request, response) => ctrl.proxy(context, request, response, 'get', '/api/admin/audit'),
  );
  router.post(
    { path: '/api/phase/assistant/chat', validate: false, options: { body: { maxBytes: 256 * 1024 } } },
    (context, request, response) => ctrl.proxy(context, request, response, 'post', '/api/assistant/chat'),
  );
}
