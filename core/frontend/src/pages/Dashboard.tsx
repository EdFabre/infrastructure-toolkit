import React, { useState } from 'react';
import { usePerformanceDashboard, usePerformanceSummary } from '@/hooks/usePerformance';
import { useMetricsWebSocket } from '@/hooks/useWebSocket';
import { ServerCard } from '@/components/ServerCard';
import { MetricsChart } from '@/components/MetricsChart';
import { AlertSystem } from '@/components/AlertSystem';
import { Server, AlertCircle, CheckCircle, AlertTriangle, Activity } from 'lucide-react';

export const Dashboard: React.FC = () => {
  const { data: dashboard, isLoading, error } = usePerformanceDashboard();
  const { data: summary } = usePerformanceSummary();
  const { metrics: liveMetrics, isConnected } = useMetricsWebSocket();
  const [selectedMetric, setSelectedMetric] = useState<'cpu' | 'memory' | 'disk'>('memory');

  // Use live metrics if available, otherwise fall back to HTTP polling
  const servers = liveMetrics?.servers || dashboard?.servers || [];

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

        {/* Summary Stats */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div className="card border border-green-500/50">
              <div className="flex items-center gap-3">
                <CheckCircle className="h-8 w-8 text-green-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{summary.healthy}</p>
                  <p className="text-sm text-slate-400">Healthy</p>
                </div>
              </div>
            </div>

            <div className="card border border-yellow-500/50">
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-8 w-8 text-yellow-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{summary.warning}</p>
                  <p className="text-sm text-slate-400">Warning</p>
                </div>
              </div>
            </div>

            <div className="card border border-red-500/50">
              <div className="flex items-center gap-3">
                <AlertCircle className="h-8 w-8 text-red-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{summary.critical}</p>
                  <p className="text-sm text-slate-400">Critical</p>
                </div>
              </div>
            </div>

            <div className="card border border-slate-500/50">
              <div className="flex items-center gap-3">
                <Server className="h-8 w-8 text-slate-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{summary.unreachable}</p>
                  <p className="text-sm text-slate-400">Unreachable</p>
                </div>
              </div>
            </div>
          </div>
        )}

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

        {/* Server Grid */}
        <div>
          <h2 className="text-xl font-semibold text-white mb-4">Server Details</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {servers.map((server) => (
              <ServerCard key={server.server} metrics={server} />
            ))}
          </div>
        </div>

        {/* Alert System */}
        <AlertSystem servers={servers} />
      </div>
    </div>
  );
};
