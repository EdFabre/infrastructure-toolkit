import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/services/api';

export function usePerformanceDashboard() {
  return useQuery({
    queryKey: ['performance', 'dashboard'],
    queryFn: () => apiClient.getPerformanceDashboard(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useServerMetrics(server: string) {
  return useQuery({
    queryKey: ['performance', 'server', server],
    queryFn: () => apiClient.getServerMetrics(server),
    refetchInterval: 30000,
    enabled: !!server,
  });
}

export function usePerformanceSummary() {
  return useQuery({
    queryKey: ['performance', 'summary'],
    queryFn: () => apiClient.getPerformanceSummary(),
    refetchInterval: 30000,
  });
}
