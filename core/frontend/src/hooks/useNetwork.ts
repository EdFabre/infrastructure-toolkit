import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/services/api';

export function useNetworkHealth() {
  return useQuery({
    queryKey: ['network', 'health'],
    queryFn: () => apiClient.getNetworkHealth(),
    refetchInterval: 30000,
  });
}

export function useNetworks() {
  return useQuery({
    queryKey: ['network', 'networks'],
    queryFn: () => apiClient.getNetworks(),
    refetchInterval: 60000,
  });
}

export function useWifiNetworks() {
  return useQuery({
    queryKey: ['network', 'wifi'],
    queryFn: () => apiClient.getWifiNetworks(),
    refetchInterval: 60000,
  });
}

export function useNetworkDevices() {
  return useQuery({
    queryKey: ['network', 'devices'],
    queryFn: () => apiClient.getNetworkDevices(),
    refetchInterval: 30000,
  });
}

export function useNetworkClients(params?: { top?: number; sortBy?: string }) {
  return useQuery({
    queryKey: ['network', 'clients', params],
    queryFn: () => apiClient.getNetworkClients(params),
    refetchInterval: 30000,
  });
}
