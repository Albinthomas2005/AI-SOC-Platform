import React from 'react';
import { Route } from 'react-router-dom';
import { AiSocDashboard } from './index';

/** Shared route element so the hook-using page is mounted as a component. */
export const aiSocDashboardRoute = (
  <Route path='/ai-soc-dashboard' exact component={AiSocDashboard} />
);
