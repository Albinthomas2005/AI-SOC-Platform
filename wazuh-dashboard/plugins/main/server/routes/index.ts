import { IRouter } from 'opensearch_dashboards/server';
import { WazuhApiRoutes } from './wazuh-api';
import { WazuhElasticRoutes } from './wazuh-elastic';
import { WazuhHostsRoutes } from './wazuh-hosts';
import { WazuhUtilsRoutes, UiLogsRoutes } from './wazuh-utils';
import { WazuhReportingRoutes } from './wazuh-reporting';
import { WazuhAiRoutes } from './wazuh-ai';
import { WazuhHuntingRoutes } from './wazuh-hunting';
import { WazuhPhaseRoutes } from './wazuh-phase';

export const setupRoutes = (router: IRouter, services) => {
  WazuhApiRoutes(router, services);
  WazuhElasticRoutes(router, services);
  WazuhHostsRoutes(router, services);
  WazuhUtilsRoutes(router, services);
  WazuhReportingRoutes(router, services);
  WazuhAiRoutes(router);
  WazuhHuntingRoutes(router);
  WazuhPhaseRoutes(router);
  UiLogsRoutes(router, services);
};
