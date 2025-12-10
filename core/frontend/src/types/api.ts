// Performance API Types
export interface ContainerMetrics {
  cpu_seconds?: number;
  memory_bytes?: number;
  memory_mb?: number;
  network_rx_bytes?: number;
  network_tx_bytes?: number;
}

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
  containers?: Record<string, ContainerMetrics>;
  cadvisor_available?: boolean;
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
  status: string;
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
  ssid?: string;
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
  rx_bytes: number;
  tx_bytes: number;
  is_wired: boolean;
}

// Docker API Types
export interface DockerContainer {
  id: string;
  server: string;
  name: string;
  image: string;
  status: string;
  state: string;
  created: string;
  created_at: string;
  ports: string[];
  metrics?: {
    cpu_seconds?: number;
    memory_mb?: number;
    network_rx_bytes?: number;
    network_tx_bytes?: number;
  };
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
  path?: string;
}

export interface CloudflareValidation {
  valid: boolean;
  hostname_count: number;
  issues: string[];
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
  daemon_listen?: number;
  description?: string;
}

export interface PterodactylIssue {
  node: string;
  issue: string;
  current: string;
  expected: string;
  impact: string;
  fix: string;
}

export interface PterodactylDiagnosis {
  issues: PterodactylIssue[];
  tunnel_issues: string[];
  recommendations: string[];
}

// Proxmox USB API Types
export interface USBDevice {
  device_id: string;
  vendor_id: string;
  product_id: string;
  product_name: string;
  speed: string;
  port: number;
  host_bus?: number;
  host_port?: string;
  is_healthy: boolean;
}

export interface USBHealthStatus {
  vm_id: number;
  total_devices: number;
  healthy_devices: number;
  unhealthy_devices: number;
  status: 'healthy' | 'unhealthy';
  devices: USBDevice[];
  issues: USBIssue[];
}

export interface USBIssue {
  device_id: string;
  product: string;
  issue: string;
  expected: string;
}

export interface USBResetResponse {
  success: boolean;
  message: string;
  new_status: USBHealthStatus;
}

export interface USBAutoFixResponse {
  status: 'no_action_needed' | 'fixed' | 'partial';
  message?: string;
  devices_checked?: number;
  fixed_devices?: string[];
  failed_devices?: string[];
  new_health?: USBHealthStatus;
}

export interface ProxmoxHealth {
  status: 'healthy' | 'unhealthy';
  checks: Record<string, boolean | string>;
  host: string;
  ip: string;
}
