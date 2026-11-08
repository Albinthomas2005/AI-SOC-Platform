import { IRouter } from 'opensearch_dashboards/server';
import { schema } from '@osd/config-schema';
import { WazuhHuntingCtrl } from '../controllers';

export function WazuhHuntingRoutes(router: IRouter) {
  const ctrl = new WazuhHuntingCtrl();
  router.post(
    {
      path: '/api/hunts/run',
      validate: { body: schema.object({ question: schema.string() }) },
      options: { body: { maxBytes: 8192 } },
    },
    (context, request, response) => ctrl.runHunt(context, request, response),
  );
}
