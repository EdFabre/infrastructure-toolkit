import type {
  DashboardResponse,
  SummaryResponse,
  ServerMetrics,
  SystemHealth,
  NetworkConfig,
  WifiNetwork,
  NetworkDevice,
  NetworkClient,
  DockerContainer,
  DockerHealthResponse,
  CloudflareHostname,
  CloudflareValidation,
  PterodactylNode,
  PterodactylDiagnosis,
  USBHealthStatus,
  USBResetResponse,
  USBAutoFixResponse,
  ProxmoxHealth,
} from '@/types/api';

const API_BASE = '/api';

class ApiClient {
  private async fetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
      ...options,
    });

    if (!response.ok) {
      throw new Error(`API Error: ${response.statusText}`);
    }

    return response.json();
  }

  // Performance API
  async getPerformanceDashboard(): Promise<DashboardResponse> {
    return this.fetch<DashboardResponse>('/perf/dashboard');
  }

  async getServerMetrics(server: string): Promise<ServerMetrics> {
    return this.fetch<ServerMetrics>(`/perf/servers/${server}/metrics`);
  }

  async getPerformanceSummary(): Promise<SummaryResponse> {
    return this.fetch<SummaryResponse>('/perf/summary');
  }

  // Network API
  async getNetworkHealth(): Promise<SystemHealth> {
    return this.fetch<SystemHealth>('/net/health');
  }

  async getNetworks(): Promise<{ networks: NetworkConfig[] }> {
    return this.fetch<{ networks: NetworkConfig[] }>('/net/networks');
  }

  async getWifiNetworks(): Promise<{ wlans: WifiNetwork[] }> {
    return this.fetch<{ wlans: WifiNetwork[] }>('/net/wifi');
  }

  async getNetworkDevices(): Promise<{ devices: NetworkDevice[] }> {
    return this.fetch<{ devices: NetworkDevice[] }>('/net/devices');
  }

  async getNetworkClients(params?: { top?: number; sortBy?: string }): Promise<{ clients: NetworkClient[]; total: number }> {
    const queryParams = new URLSearchParams();
    if (params?.top) queryParams.append('top', params.top.toString());
    if (params?.sortBy) queryParams.append('sortBy', params.sortBy);

    const query = queryParams.toString();
    return this.fetch<{ clients: NetworkClient[]; total: number }>(
      `/net/clients${query ? `?${query}` : ''}`
    );
  }

  // Docker API
  async getDockerContainers(server?: string): Promise<{ containers: DockerContainer[]; total: number }> {
    const query = server ? `?server=${server}` : '';
    return this.fetch<{ containers: DockerContainer[]; total: number }>(`/docker/containers${query}`);
  }

  async getDockerHealth(server: string): Promise<DockerHealthResponse> {
    return this.fetch<DockerHealthResponse>(`/docker/servers/${server}/health`);
  }

  // Cloudflare API
  async getCloudflareHostnames(domain: string = 'haymoed'): Promise<{ hostnames: CloudflareHostname[] }> {
    return this.fetch<{ hostnames: CloudflareHostname[] }>(`/cloudflare/hostnames?domain=${domain}`);
  }

  async validateCloudflareConfig(domain: string = 'haymoed'): Promise<CloudflareValidation> {
    return this.fetch<CloudflareValidation>(`/cloudflare/validate?domain=${domain}`);
  }

  // Pterodactyl API
  async getPterodactylNodes(): Promise<{ nodes: PterodactylNode[] }> {
    return this.fetch<{ nodes: PterodactylNode[] }>('/pterodactyl/nodes');
  }

  async diagnosePterodactyl(): Promise<PterodactylDiagnosis> {
    return this.fetch<PterodactylDiagnosis>('/pterodactyl/diagnose');
  }

  // NAS API
  async getNASSystems(): Promise<{ systems: any[]; total: number }> {
    return this.fetch<{ systems: any[]; total: number }>('/nas/systems');
  }

  async getNASHealth(): Promise<{ status: string; checks: any; message: string }> {
    return this.fetch<{ status: string; checks: any; message: string }>('/nas/health');
  }

  // Proxmox USB API
  async getProxmoxHealth(host: string = 'pve3'): Promise<ProxmoxHealth> {
    return this.fetch<ProxmoxHealth>(`/proxmox/health?host=${host}`);
  }

  async getUSBStatus(vmId: number, host: string = 'pve3'): Promise<USBHealthStatus> {
    return this.fetch<USBHealthStatus>(`/proxmox/vms/${vmId}/usb?host=${host}`);
  }

  async resetUSBDevice(vmId: number, deviceId: string, host: string = 'pve3'): Promise<USBResetResponse> {
    return this.fetch<USBResetResponse>(`/proxmox/vms/${vmId}/usb/reset?host=${host}`, {
      method: 'POST',
      body: JSON.stringify({ device_id: deviceId, use_hostport: true }),
    });
  }

  async autoFixUSB(vmId: number, host: string = 'pve3'): Promise<USBAutoFixResponse> {
    return this.fetch<USBAutoFixResponse>(`/proxmox/vms/${vmId}/usb/auto-fix?host=${host}`, {
      method: 'POST',
    });
  }
}

export const apiClient = new ApiClient();
