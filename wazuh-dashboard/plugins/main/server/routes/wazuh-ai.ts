/*
 * Wazuh app - Module for SOC AI analysis routes
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
import { WazuhAiCtrl } from '../controllers';
import { IRouter } from 'opensearch_dashboards/server';
import { schema } from '@osd/config-schema';

const MAX_AI_ALERT_BYTES = 256 * 1024;

export function WazuhAiRoutes(router: IRouter) {
  const ctrl = new WazuhAiCtrl();

  router.post(
    {
      path: '/api/ai/analyze-alert',
      validate: {
        body: schema.object({
          index: schema.string(),
          id: schema.string(),
        }),
      },
      options: {
        body: {
          maxBytes: MAX_AI_ALERT_BYTES,
        },
      },
    },
    (context, request, response) =>
      ctrl.analyzeAlert(context, request, response),
  );
  router.post(
    {
      path: '/api/training/attempts/{id}/coaching',
      validate: {
        params: schema.object({ id: schema.string() }),
        body: schema.object({}),
      },
    },
    (context, request, response) =>
      ctrl.proxyTraining(context, request, response, `/attempts/${encodeURIComponent(request.params.id)}/coaching`, 'post'),
  );

  router.post(
    {
      path: '/api/ai/generate-report',
      validate: {
        body: schema.object({
          index: schema.string(),
          id: schema.string(),
          analyst_notes: schema.maybe(schema.string()),
        }),
      },
      options: {
        body: {
          maxBytes: MAX_AI_ALERT_BYTES,
        },
      },
    },
    (context, request, response) =>
      ctrl.generateReport(context, request, response),
  );

  router.post(
    {
      path: '/api/ai/analysis/decision',
      validate: {
        body: schema.object({
          analysis_id: schema.string(),
          decision: schema.string(),
          note: schema.maybe(schema.string()),
          edited_analysis: schema.maybe(schema.string()),
        }),
      },
      options: {
        body: {
          maxBytes: MAX_AI_ALERT_BYTES,
        },
      },
    },
    (context, request, response) =>
      ctrl.recordAnalysisDecision(context, request, response),
  );

  router.get(
    { path: '/api/training/scenarios', validate: false },
    (context, request, response) =>
      ctrl.proxyTraining(context, request, response, '/scenarios', 'get'),
  );
  router.get(
    { path: '/api/training/progress', validate: false },
    (context, request, response) =>
      ctrl.proxyTraining(context, request, response, '/progress', 'get'),
  );
  router.get(
    {
      path: '/api/training/mitre',
      validate: { query: schema.object({ q: schema.maybe(schema.string()) }) },
    },
    (context, request, response) =>
      ctrl.proxyTraining(context, request, response, '/mitre', 'get'),
  );
  router.get(
    {
      path: '/api/training/scenarios/{id}',
      validate: { params: schema.object({ id: schema.string() }) },
    },
    (context, request, response) =>
      ctrl.proxyTraining(context, request, response, `/scenarios/${encodeURIComponent(request.params.id)}`, 'get'),
  );
  router.get(
    {
      path: '/api/training/scenarios/{id}/hints',
      validate: {
        params: schema.object({ id: schema.string() }),
        query: schema.object({ level: schema.string() }),
      },
    },
    (context, request, response) =>
      ctrl.proxyTraining(context, request, response, `/scenarios/${encodeURIComponent(request.params.id)}/hints`, 'get'),
  );
  router.post(
    {
      path: '/api/training/attempts',
      validate: {
        body: schema.object({
          scenario_id: schema.string(),
          verdict: schema.string(),
          escalate: schema.boolean(),
          mitre_ids: schema.arrayOf(schema.string()),
          report_text: schema.string(),
          time_spent: schema.number(),
        }),
      },
      options: { body: { maxBytes: 256 * 1024 } },
    },
    (context, request, response) =>
      ctrl.proxyTraining(context, request, response, '/attempts', 'post'),
  );
}
