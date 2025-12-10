import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/services/api';
import { usePerformanceDashboard, usePerformanceSummary } from '@/hooks/usePerformance';
import { useMetricsWebSocket } from '@/hooks/useWebSocket';
import { ServerCard } from '@/components/ServerCard';
import { MetricsChart } from '@/components/MetricsChart';
import { AlertSystem } from '@/components/AlertSystem';
import { ResponsiveTabs } from '@/components/ResponsiveTabs';
import { Server, AlertCircle, CheckCircle, AlertTriangle, Activity, Wifi, Container, Cloud, Gamepad2, LayoutDashboard } from 'lucide-react';
import { Link } from 'react-router-dom';

export const Dashboard: React.FC = () => {
  const { data: dashboard, isLoading, error } = usePerformanceDashboard();
  const { data: summary } = usePerformanceSummary();
  const { metrics: liveMetrics, isConnected } = useMetricsWebSocket();
  const [selectedMetric, setSelectedMetric] = useState<'cpu' | 'memory' | 'disk'>('memory');
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'servers'>('overview');

  // Fetch additional infrastructure data
  const { data: networkData } = useQuery({
    queryKey: ['network', 'health'],
    queryFn: () => apiClient.getNetworkHealth(),
    refetchInterval: 30000,
  });

  const { data: dockerData } = useQuery({
    queryKey: ['docker', 'containers'],
    queryFn: () => apiClient.getDockerContainers(),
    refetchInterval: 30000,
  });

  const { data: cloudflareData } = useQuery({
    queryKey: ['cloudflare', 'hostnames'],
    queryFn: () => apiClient.getCloudflareHostnames(),
    refetchInterval: 60000,
  });

  const { data: pterodactylData } = useQuery({
    queryKey: ['pterodactyl', 'nodes'],
    queryFn: () => apiClient.getPterodactylNodes(),
    refetchInterval: 30000,
  });

  // Use live metrics if available, otherwise fall back to HTTP polling
  const servers = liveMetrics?.servers || dashboard?.servers || [];
  const dockerContainers = dockerData?.containers || [];
  const cloudflareHostnames = cloudflareData?.hostnames || [];
  const gameNodes = pterodactylData?.nodes || [];

  // Filter servers based on selected status
  const filteredServers = statusFilter
    ? servers.filter((s: any) => s.status === statusFilter)
    : servers;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading server metrics...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="card max-w-md border-red-500/50">
          <AlertCircle className="h-12 w-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white text-center mb-2">
            Error Loading Dashboard
          </h2>
          <p className="text-slate-400 text-center">
            {error instanceof Error ? error.message : 'Unknown error occurred'}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white mb-2">
                Infrastructure Dashboard
              </h1>
              <p className="text-slate-400">
                Real-time monitoring across {servers.length || 0} servers
              </p>
            </div>
            {isConnected && (
              <div className="flex items-center gap-2 px-4 py-2 bg-green-500/20 text-green-400 rounded-full border border-green-500/50">
                <Activity className="h-4 w-4 animate-pulse" />
                <span className="text-sm font-medium">Live Updates</span>
              </div>
            )}
          </div>
        </div>

        {/* Dashboard Tabs */}
        <ResponsiveTabs
          tabs={[
            { id: 'overview', label: 'Overview', icon: LayoutDashboard },
            { id: 'servers', label: 'Server Details', icon: Server },
          ]}
          activeTab={activeTab}
          onChange={(id) => setActiveTab(id as 'overview' | 'servers')}
        />

        {/* Overview Tab Content */}
        {activeTab === 'overview' && (
          <>
            {/* Server Health Summary - Interactive Consolidated Card */}
            {summary && (
          <div className="card border border-slate-600/50 p-4 mb-8">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-lg font-semibold text-white">Server Status</h3>
              {statusFilter && (
                <button
                  onClick={() => setStatusFilter(null)}
                  className="text-xs text-primary-400 hover:text-primary-300"
                >
                  Clear filter
                </button>
              )}
            </div>
            <div className="flex flex-wrap gap-3">
              {[
                { status: 'healthy', icon: CheckCircle, color: 'green', count: summary.healthy },
                { status: 'warning', icon: AlertTriangle, color: 'yellow', count: summary.warning },
                { status: 'critical', icon: AlertCircle, color: 'red', count: summary.critical },
                { status: 'unreachable', icon: Server, color: 'slate', count: summary.unreachable },
              ].map(({ status, icon: Icon, color, count }) => (
                <button
                  key={status}
                  onClick={() => setStatusFilter(statusFilter === status ? null : status)}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${
                    statusFilter === status
                      ? `bg-${color}-500/20 ring-1 ring-${color}-500`
                      : 'hover:bg-slate-700'
                  }`}
                >
                  <Icon className={`h-4 w-4 text-${color}-500`} />
                  <span className="text-white font-medium">{count}</span>
                  <span className="text-slate-400 text-sm capitalize">{status}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Infrastructure Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {/* Network Overview */}
          <Link to="/network" className="card border border-blue-500/50 hover:border-blue-500 transition-colors cursor-pointer group">
            <div className="flex items-start justify-between mb-3">
              <div className="p-2 bg-blue-500/20 rounded-lg">
                <Wifi className="h-6 w-6 text-blue-400" />
              </div>
              <span className="text-xs text-slate-500 group-hover:text-slate-400">View Details →</span>
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">Network</h3>
            {networkData ? (
              <div className="space-y-1">
                <p className="text-sm text-slate-400">
                  <span className={networkData.status === 'healthy' ? 'text-green-400' : 'text-red-400'}>
                    {networkData.status === 'healthy' ? '● Online' : '● Offline'}
                  </span>
                </p>
                <p className="text-xs text-slate-500">
                  {Object.keys(networkData.subsystems || {}).length} subsystems monitored
                </p>
              </div>
            ) : (
              <p className="text-sm text-slate-500">Loading...</p>
            )}
          </Link>

          {/* Docker Overview */}
          <Link to="/docker" className="card border border-purple-500/50 hover:border-purple-500 transition-colors cursor-pointer group">
            <div className="flex items-start justify-between mb-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <Container className="h-6 w-6 text-purple-400" />
              </div>
              <span className="text-xs text-slate-500 group-hover:text-slate-400">View Details →</span>
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">Containers</h3>
            {dockerData ? (
              <div className="space-y-1">
                <p className="text-2xl font-bold text-white">{dockerData.total || 0}</p>
                <p className="text-xs text-slate-500">
                  {dockerContainers.filter(c => c.state === 'running').length} running
                </p>
              </div>
            ) : (
              <p className="text-sm text-slate-500">Loading...</p>
            )}
          </Link>

          {/* Cloudflare Overview */}
          <Link to="/cloudflare" className="card border border-orange-500/50 hover:border-orange-500 transition-colors cursor-pointer group">
            <div className="flex items-start justify-between mb-3">
              <div className="p-2 bg-orange-500/20 rounded-lg">
                <Cloud className="h-6 w-6 text-orange-400" />
              </div>
              <span className="text-xs text-slate-500 group-hover:text-slate-400">View Details →</span>
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">Cloudflare</h3>
            {cloudflareData ? (
              <div className="space-y-1">
                <p className="text-2xl font-bold text-white">{cloudflareHostnames.length}</p>
                <p className="text-xs text-slate-500">tunnel hostnames</p>
              </div>
            ) : (
              <p className="text-sm text-slate-500">Loading...</p>
            )}
          </Link>

          {/* Game Servers Overview */}
          <Link to="/pterodactyl" className="card border border-pink-500/50 hover:border-pink-500 transition-colors cursor-pointer group">
            <div className="flex items-start justify-between mb-3">
              <div className="p-2 bg-pink-500/20 rounded-lg">
                <Gamepad2 className="h-6 w-6 text-pink-400" />
              </div>
              <span className="text-xs text-slate-500 group-hover:text-slate-400">View Details →</span>
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">Game Servers</h3>
            {pterodactylData ? (
              <div className="space-y-1">
                <p className="text-2xl font-bold text-white">{gameNodes.length}</p>
                <p className="text-xs text-slate-500">
                  {gameNodes.reduce((sum, n) => sum + (n.allocated_memory || 0), 0) / 1024 | 0} GB allocated
                </p>
              </div>
            ) : (
              <p className="text-sm text-slate-500">Loading...</p>
            )}
          </Link>
        </div>

        {/* Metrics Visualization */}
        <div className="mb-8">
          <div className="flex items-center gap-4 mb-4">
            <h2 className="text-xl font-semibold text-white">Metrics Overview</h2>
            <div className="flex gap-2">
              {(['cpu', 'memory', 'disk'] as const).map((metric) => (
                <button
                  key={metric}
                  onClick={() => setSelectedMetric(metric)}
                  className={`px-4 py-2 rounded-md transition-colors ${
                    selectedMetric === metric
                      ? 'bg-primary-600 text-white'
                      : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                  }`}
                >
                  {metric.charAt(0).toUpperCase() + metric.slice(1)}
                </button>
              ))}
            </div>
          </div>
          <MetricsChart servers={servers} metric={selectedMetric} />
        </div>
          </>
        )}

        {/* Servers Tab Content */}
        {activeTab === 'servers' && (
        <div>
          <h2 className="text-xl font-semibold text-white mb-4">
            Server Details {statusFilter && <span className="text-sm text-slate-400">({statusFilter})</span>}
          </h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {filteredServers.map((server: any) => (
              <ServerCard key={server.server} metrics={server} />
            ))}
          </div>
        </div>
        )}

        {/* Alert System */}
        <AlertSystem servers={servers} />
      </div>
    </div>
  );
};
