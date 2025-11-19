// Performance API Types
export interface ServerMetrics {
  server: string;
  status: 'healthy' | 'warning' | 'critical' | 'unreachable';
  reachable: boolean;
  cpu_load?: {
    '1min': number;
    '5min': number;
    '15min': number;
  };
  memory?: {
    total_bytes: number;
    used_bytes: number;
    free_bytes: number;
    used_percent: number;
  };
  disk?: {
    total_bytes: number;
    used_bytes: number;
    free_bytes: number;
    used_percent: number;
  };
  uptime_seconds?: number;
  timestamp?: string;
}

export interface DashboardResponse {
  servers: ServerMetrics[];
}

export interface SummaryResponse {
  total_servers: number;
  healthy: number;
  warning: number;
  critical: number;
  unreachable: number;
  average_cpu_load: number;
  average_memory_percent: number;
  average_disk_percent: number;
}

// Network API Types
export interface SystemHealth {
  subsystems: Record<string, {
    status: string;
    description: string;
  }>;
  overall_status: string;
}

export interface NetworkConfig {
  id: string;
  name: string;
  purpose: string;
  vlan_enabled: boolean;
  vlan?: number;
  domain_name?: string;
  subnet?: string;
  dhcp_enabled?: boolean;
}

export interface WifiNetwork {
  id: string;
  name: string;
  enabled: boolean;
  security: string;
  minrate_ng_data_rate_kbps?: number;
  minrate_na_data_rate_kbps?: number;
}

export interface NetworkDevice {
  id: string;
  name: string;
  type: string;
  model: string;
  ip: string;
  mac: string;
  state: number;
  uptime: number;
}

export interface NetworkClient {
  id: string;
  hostname?: string;
  name?: string;
  ip: string;
  mac: string;
  network: string;
  signal?: number;
  total_bytes: number;
  is_wired: boolean;
}

// Docker API Types
export interface DockerContainer {
  server: string;
  name: string;
  image: string;
  status: string;
  state: string;
  created_at: string;
  ports: string[];
}

export interface DockerHealthResponse {
  reachable: boolean;
  docker_running: boolean;
  containers_running: number;
  containers_total: number;
  containers: DockerContainer[];
}

// Cloudflare API Types
export interface CloudflareHostname {
  hostname: string;
  service: string;
}

export interface CloudflareValidation {
  is_valid: boolean;
  errors: string[];
}

// Pterodactyl API Types
export interface PterodactylNode {
  id: number;
  name: string;
  fqdn: string;
  scheme: string;
  memory: number;
  disk: number;
  allocated_memory: number;
  allocated_disk: number;
}

export interface PterodactylDiagnosis {
  tunnel_issues: string[];
  recommendations: string[];
}
