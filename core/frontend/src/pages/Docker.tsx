import React, { useState, useMemo } from 'react';
import { useDockerContainers } from '@/hooks/useDocker';
import { usePerformanceDashboard } from '@/hooks/usePerformance';
import { StatusBadge } from '@/components/StatusBadge';
import { Container, Server, Play, Square, AlertCircle, Cpu, MemoryStick, Network } from 'lucide-react';

const SERVERS = [
  'boss-01', 'boss-02', 'boss-03', 'boss-04', 'boss-05',
  'boss-06', 'boss-07', 'king-01'
];

// Helper function to format bytes to human-readable format
function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null) return 'N/A';
  if (bytes === 0) return '0 B';

  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export const Docker: React.FC = () => {
  const [selectedServer, setSelectedServer] = useState<string>('all');
  const { data: containersData, isLoading: loadingContainers, error: containerError } = useDockerContainers(
    selectedServer === 'all' ? undefined : selectedServer
  );
  const { data: performanceData, isLoading: loadingPerformance } = usePerformanceDashboard();

  const isLoading = loadingContainers || loadingPerformance;
  const error = containerError;

  const containers = containersData?.containers || [];
  const total = containersData?.total || 0;

  // Merge container resource metrics from cAdvisor
  const containersWithMetrics = useMemo(() => {
    if (!performanceData?.servers) return containers;

    return containers.map((container) => {
      // Find the server's performance data
      const serverPerf = performanceData.servers.find((s: any) => s.server === container.server);

      if (!serverPerf?.containers) return container;

      // Find the container's metrics in cAdvisor data
      const containerMetrics = serverPerf.containers[container.name];

      if (!containerMetrics) return container;

      // Merge metrics into container object
      return {
        ...container,
        metrics: {
          cpu_seconds: containerMetrics.cpu_seconds,
          memory_mb: containerMetrics.memory_mb,
          network_rx_bytes: containerMetrics.network_rx_bytes,
          network_tx_bytes: containerMetrics.network_tx_bytes,
        },
      };
    });
  }, [containers, performanceData]);

  // Group containers by server
  const containersByServer = containersWithMetrics.reduce((acc, container) => {
    const server = container.server || 'unknown';
    if (!acc[server]) acc[server] = [];
    acc[server].push(container);
    return acc;
  }, {} as Record<string, typeof containersWithMetrics>);

  const runningCount = containersWithMetrics.filter(c => c.state === 'running').length;
  const stoppedCount = containersWithMetrics.filter(c => c.state !== 'running').length;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading container information...</p>
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
            Error Loading Containers
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
          <h1 className="text-3xl font-bold text-white mb-2">
            Docker Container Management
          </h1>
          <p className="text-slate-400">
            Monitor and manage containers across all boss servers
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="card border border-primary-500/50">
            <div className="flex items-center gap-3">
              <Container className="h-8 w-8 text-primary-400" />
              <div>
                <p className="text-2xl font-bold text-white">{total}</p>
                <p className="text-sm text-slate-400">Total Containers</p>
              </div>
            </div>
          </div>
          <div className="card border border-green-500/50">
            <div className="flex items-center gap-3">
              <Play className="h-8 w-8 text-green-400" />
              <div>
                <p className="text-2xl font-bold text-white">{runningCount}</p>
                <p className="text-sm text-slate-400">Running</p>
              </div>
            </div>
          </div>
          <div className="card border border-red-500/50">
            <div className="flex items-center gap-3">
              <Square className="h-8 w-8 text-red-400" />
              <div>
                <p className="text-2xl font-bold text-white">{stoppedCount}</p>
                <p className="text-sm text-slate-400">Stopped</p>
              </div>
            </div>
          </div>
        </div>

        {/* Server Filter */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-slate-400 mb-2">
            Filter by Server
          </label>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedServer('all')}
              className={`px-4 py-2 rounded-md transition-colors ${
                selectedServer === 'all'
                  ? 'bg-primary-600 text-white'
                  : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
              }`}
            >
              All Servers
            </button>
            {SERVERS.map((server) => (
              <button
                key={server}
                onClick={() => setSelectedServer(server)}
                className={`px-4 py-2 rounded-md transition-colors ${
                  selectedServer === server
                    ? 'bg-primary-600 text-white'
                    : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                }`}
              >
                {server}
              </button>
            ))}
          </div>
        </div>

        {/* Containers by Server */}
        <div className="space-y-6">
          {Object.entries(containersByServer).map(([server, serverContainers]) => (
            <div key={server} className="card">
              <div className="flex items-center gap-3 mb-4">
                <Server className="h-6 w-6 text-primary-400" />
                <h2 className="text-xl font-semibold text-white">{server}</h2>
                <span className="text-sm text-slate-400">
                  ({serverContainers.length} containers)
                </span>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
                {serverContainers.map((container) => (
                  <div
                    key={container.id}
                    className="bg-slate-700/50 rounded-lg p-4 border border-slate-600"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <h3 className="font-medium text-white truncate" title={container.name}>
                          {container.name}
                        </h3>
                        <p className="text-xs text-slate-500 truncate mt-1" title={container.image}>
                          {container.image}
                        </p>
                      </div>
                      <StatusBadge
                        status={container.state === 'running' ? 'healthy' : 'critical'}
                      />
                    </div>
                    <div className="space-y-2 text-xs">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Status:</span>
                        <span className={`font-medium ${
                          container.state === 'running' ? 'text-green-400' : 'text-red-400'
                        }`}>
                          {container.status}
                        </span>
                      </div>
                      {container.ports && container.ports.length > 0 && (
                        <div className="flex justify-between">
                          <span className="text-slate-400">Ports:</span>
                          <span className="text-white font-mono">
                            {container.ports.join(', ')}
                          </span>
                        </div>
                      )}
                      {container.created && (
                        <div className="flex justify-between">
                          <span className="text-slate-400">Created:</span>
                          <span className="text-white">
                            {new Date(container.created).toLocaleDateString()}
                          </span>
                        </div>
                      )}

                      {/* Container Resource Metrics */}
                      {container.metrics && (
                        <>
                          <div className="border-t border-slate-600 my-2 pt-2">
                            <p className="text-slate-500 font-medium mb-1">Resources</p>
                          </div>
                          {container.metrics.memory_mb !== undefined && (
                            <div className="flex justify-between items-center">
                              <span className="text-slate-400 flex items-center gap-1">
                                <MemoryStick className="h-3 w-3" />
                                Memory:
                              </span>
                              <span className="text-blue-400 font-medium">
                                {container.metrics.memory_mb.toFixed(0)} MB
                              </span>
                            </div>
                          )}
                          {container.metrics.cpu_seconds !== undefined && (
                            <div className="flex justify-between items-center">
                              <span className="text-slate-400 flex items-center gap-1">
                                <Cpu className="h-3 w-3" />
                                CPU Time:
                              </span>
                              <span className="text-yellow-400 font-medium">
                                {(container.metrics.cpu_seconds / 3600).toFixed(1)}h
                              </span>
                            </div>
                          )}
                          {(container.metrics.network_rx_bytes !== undefined || container.metrics.network_tx_bytes !== undefined) && (
                            <div className="flex justify-between items-center">
                              <span className="text-slate-400 flex items-center gap-1">
                                <Network className="h-3 w-3" />
                                Network:
                              </span>
                              <span className="text-green-400 font-medium">
                                ↓ {formatBytes(container.metrics.network_rx_bytes)} / ↑ {formatBytes(container.metrics.network_tx_bytes)}
                              </span>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {containersWithMetrics.length === 0 && (
          <div className="card text-center py-12">
            <Container className="h-16 w-16 text-slate-600 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No Containers Found</h3>
            <p className="text-slate-400">
              {selectedServer === 'all'
                ? 'No containers are currently running on any server'
                : `No containers found on ${selectedServer}`}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
