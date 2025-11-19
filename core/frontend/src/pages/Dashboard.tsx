import React from 'react';
import { usePerformanceDashboard, usePerformanceSummary } from '@/hooks/usePerformance';
import { ServerCard } from '@/components/ServerCard';
import { Server, AlertCircle, CheckCircle, AlertTriangle } from 'lucide-react';

export const Dashboard: React.FC = () => {
  const { data: dashboard, isLoading, error } = usePerformanceDashboard();
  const { data: summary } = usePerformanceSummary();

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
          <h1 className="text-3xl font-bold text-white mb-2">
            Infrastructure Dashboard
          </h1>
          <p className="text-slate-400">
            Real-time monitoring across {dashboard?.servers.length || 0} servers
          </p>
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

        {/* Server Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
          {dashboard?.servers.map((server) => (
            <ServerCard key={server.server} metrics={server} />
          ))}
        </div>
      </div>
    </div>
  );
};
