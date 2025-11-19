import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/services/api';

export function useDockerContainers(server?: string) {
  return useQuery({
    queryKey: ['docker', 'containers', server],
    queryFn: () => apiClient.getDockerContainers(server),
    refetchInterval: 30000,
  });
}

export function useDockerHealth(server: string) {
  return useQuery({
    queryKey: ['docker', 'health', server],
    queryFn: () => apiClient.getDockerHealth(server),
    refetchInterval: 30000,
    enabled: !!server,
  });
}
