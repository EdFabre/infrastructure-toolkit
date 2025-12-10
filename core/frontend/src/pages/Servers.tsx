import React, { useState } from 'react';
import { usePerformanceDashboard } from '@/hooks/usePerformance';
import { ServerCard } from '@/components/ServerCard';
import { Server, AlertCircle, Filter, BarChart3 } from 'lucide-react';

export const Servers: React.FC = () => {
  const { data: dashboard, isLoading, error } = usePerformanceDashboard();
  const [filterStatus, setFilterStatus] = useState<'all' | 'healthy' | 'warning' | 'critical'>('all');
  const [sortBy, setSortBy] = useState<'name' | 'cpu' | 'memory' | 'disk'>('name');

  const servers = dashboard?.servers || [];

  // Filter servers by status
  const filteredServers = servers.filter(server => {
    if (filterStatus === 'all') return true;

    const memoryPercent = server.memory?.used_percent || 0;
    const diskPercent = server.disk?.used_percent || 0;
    const cpuLoad = server.cpu_load?.['1min'] || 0;

    if (filterStatus === 'critical') {
      return memoryPercent > 90 || diskPercent > 90 || cpuLoad > 8;
    } else if (filterStatus === 'warning') {
      return (memoryPercent > 75 && memoryPercent <= 90) ||
             (diskPercent > 75 && diskPercent <= 90) ||
             (cpuLoad > 4 && cpuLoad <= 8);
    } else if (filterStatus === 'healthy') {
      return memoryPercent <= 75 && diskPercent <= 75 && cpuLoad <= 4;
    }
    return true;
  });

  // Sort servers
  const sortedServers = [...filteredServers].sort((a, b) => {
    switch (sortBy) {
      case 'name':
        return a.server.localeCompare(b.server);
      case 'cpu':
        return (b.cpu_load?.['1min'] || 0) - (a.cpu_load?.['1min'] || 0);
      case 'memory':
        return (b.memory?.used_percent || 0) - (a.memory?.used_percent || 0);
      case 'disk':
        return (b.disk?.used_percent || 0) - (a.disk?.used_percent || 0);
      default:
        return 0;
    }
  });

  // Calculate statistics
  const bossServers = servers.filter(s => s.server.startsWith('boss'));
  const kingServers = servers.filter(s => s.server.startsWith('king'));

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading server information...</p>
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
            Error Loading Server Data
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
            Boss & King Servers
          </h1>
          <p className="text-slate-400">
            Detailed monitoring and management for {servers.length} servers
          </p>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="card border border-blue-500/50">
            <div className="flex items-center gap-3">
              <Server className="h-8 w-8 text-blue-400" />
              <div>
                <p className="text-2xl font-bold text-white">{bossServers.length}</p>
                <p className="text-sm text-slate-400">Boss Servers</p>
              </div>
            </div>
          </div>

          <div className="card border border-purple-500/50">
            <div className="flex items-center gap-3">
              <Server className="h-8 w-8 text-purple-400" />
              <div>
                <p className="text-2xl font-bold text-white">{kingServers.length}</p>
                <p className="text-sm text-slate-400">King Servers</p>
              </div>
            </div>
          </div>

          <div className="card border border-primary-500/50">
            <div className="flex items-center gap-3">
              <BarChart3 className="h-8 w-8 text-primary-400" />
              <div>
                <p className="text-2xl font-bold text-white">{servers.length}</p>
                <p className="text-sm text-slate-400">Total Servers</p>
              </div>
            </div>
          </div>
        </div>

        {/* Filters and Sorting */}
        <div className="card mb-6">
          <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-slate-400" />
                <span className="text-sm text-slate-400">Filter:</span>
              </div>
              <div className="flex gap-2">
                {(['all', 'healthy', 'warning', 'critical'] as const).map((status) => (
                  <button
                    key={status}
                    onClick={() => setFilterStatus(status)}
                    className={`px-3 py-1.5 rounded-md text-sm transition-colors ${
                      filterStatus === status
                        ? 'bg-primary-600 text-white'
                        : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                    }`}
                  >
                    {status.charAt(0).toUpperCase() + status.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-4">
              <span className="text-sm text-slate-400">Sort by:</span>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="bg-slate-700 text-white px-3 py-1.5 rounded-md border border-slate-600 focus:border-primary-500 focus:outline-none text-sm"
              >
                <option value="name">Name</option>
                <option value="cpu">CPU Load</option>
                <option value="memory">Memory Usage</option>
                <option value="disk">Disk Usage</option>
              </select>
            </div>
          </div>
        </div>

        {/* Server Grid */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold text-white">
              Servers ({sortedServers.length})
            </h2>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {sortedServers.map((server) => (
              <ServerCard key={server.server} metrics={server} />
            ))}
          </div>

          {sortedServers.length === 0 && (
            <div className="text-center py-12">
              <Server className="h-12 w-12 text-slate-600 mx-auto mb-4" />
              <p className="text-slate-400">No servers match the current filter</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
