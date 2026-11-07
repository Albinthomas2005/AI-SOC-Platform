import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertsDataSourceRepository,
  PatternDataSource,
  ThreatHuntingDataSource,
  tParsedIndexPattern,
  useDataSource,
} from '../common/data-source';
import {
  AiSocOverviewData,
  AiSocQueryFailure,
  buildAlertSeverityAgg,
  classifyAiSocQueryFailure,
  mapAiSocOverviewResponse,
} from './data';

export type AiSocOverviewResult =
  | { status: 'loading' }
  | { status: 'available'; data: AiSocOverviewData }
  | { status: 'unavailable' | 'error'; error: AiSocQueryFailure };

const LAST_24_HOURS = { from: 'now-24h', to: 'now' };
const RECENT_ALERTS_LIMIT = 5;

/** Uses the selected, configured Wazuh 4 alert index and existing permission-aware search path. */
export function useAiSocOverview(): AiSocOverviewResult {
  const repository = useMemo(() => new AlertsDataSourceRepository(), []);
  const { isLoading, dataSource, error, fetchData } = useDataSource<
    tParsedIndexPattern,
    PatternDataSource
  >({
    DataSource: ThreatHuntingDataSource,
    repository,
  });
  const fetchDataRef = useRef(fetchData);
  fetchDataRef.current = fetchData;
  const [result, setResult] = useState<AiSocOverviewResult>({
    status: 'loading',
  });

  useEffect(() => {
    let current = true;
    if (isLoading) {
      setResult({ status: 'loading' });
      return () => {
        current = false;
      };
    }
    if (error) {
      const failure = classifyAiSocQueryFailure(error);
      setResult({
        status: failure.kind === 'unavailable' ? 'unavailable' : 'error',
        error: failure,
      });
      return () => {
        current = false;
      };
    }
    if (!dataSource) {
      setResult({ status: 'loading' });
      return () => {
        current = false;
      };
    }

    setResult({ status: 'loading' });
    fetchDataRef
      .current({
        query: { language: 'kuery', query: '' },
        dateRange: LAST_24_HOURS,
        pagination: { pageIndex: 0, pageSize: RECENT_ALERTS_LIMIT },
        sorting: { columns: [{ id: 'timestamp', direction: 'desc' }] },
        aggs: buildAlertSeverityAgg(),
      })
      .then(response => {
        if (current)
          setResult({
            status: 'available',
            data: mapAiSocOverviewResponse(response),
          });
      })
      .catch(queryError => {
        if (current) {
          const failure = classifyAiSocQueryFailure(queryError);
          setResult({
            status: failure.kind === 'unavailable' ? 'unavailable' : 'error',
            error: failure,
          });
        }
      });
    return () => {
      current = false;
    };
  }, [isLoading, error, dataSource]);

  return result;
}
