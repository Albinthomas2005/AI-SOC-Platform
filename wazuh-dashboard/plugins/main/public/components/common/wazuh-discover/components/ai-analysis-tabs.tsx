import React from 'react';
import { DocumentViewTableAndJsonPropsAdditionalTabs } from './document-view-table-and-json';
import { AIAnalysisTab } from './ai-analysis-tab';

export const createAIAnalysisTabs = (
  document: any,
): DocumentViewTableAndJsonPropsAdditionalTabs =>
  document?._index && document?._id
    ? [
        {
          id: 'ai-analysis',
          name: 'AI Analysis',
          content: (
            <AIAnalysisTab
              key={`${document._index}:${document._id}`}
              index={document._index}
              id={document._id}
            />
          ),
        },
      ]
    : [];

export const createModuleAIAnalysisTabs = (moduleId: string, document: any) =>
  ['threat-hunting', 'pm', 'mitre'].includes(moduleId)
    ? createAIAnalysisTabs(document)
    : [];
