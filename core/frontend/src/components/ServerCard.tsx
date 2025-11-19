import React from 'react';
import { Server, Cpu, HardDrive, Activity } from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import type { ServerMetrics } from '@/types/api';

interface ServerCardProps {
  metrics: ServerMetrics;
}

function formatBytes(bytes: number): string {
  const gb = bytes / (1024 ** 3);
  return `${gb.toFixed(1)} GB`;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return `${days}d ${hours}h`;
}

export const ServerCard: React.FC<ServerCardProps> = ({ metrics }) => {
  if (!metrics.reachable) {
    return (
      <div className="card border border-slate-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Server className="h-6 w-6 text-slate-400" />
            <div>
              <h3 className="text-lg font-semibold text-white">{metrics.server}</h3>
            </div>
          </div>
          <StatusBadge status="unreachable" />
        </div>
      </div>
    );
  }

  return (
    <div className="card border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <Server className="h-6 w-6 text-primary-400" />
          <div>
            <h3 className="text-lg font-semibold text-white">{metrics.server}</h3>
            {metrics.uptime_seconds && (
              <p className="text-sm text-slate-400">
                Uptime: {formatUptime(metrics.uptime_seconds)}
              </p>
            )}
          </div>
        </div>
        <StatusBadge status={metrics.status} />
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* CPU Load */}
        {metrics.cpu_load && (
          <div className="flex items-start gap-2">
            <Cpu className="h-4 w-4 text-yellow-400 mt-1" />
            <div>
              <p className="text-xs text-slate-400">CPU Load</p>
              <p className="text-lg font-semibold text-white">
                {metrics.cpu_load['1min'].toFixed(2)}
              </p>
              <p className="text-xs text-slate-500">
                5m: {metrics.cpu_load['5min'].toFixed(2)}
              </p>
            </div>
          </div>
        )}

        {/* Memory */}
        {metrics.memory && (
          <div className="flex items-start gap-2">
            <Activity className="h-4 w-4 text-green-400 mt-1" />
            <div>
              <p className="text-xs text-slate-400">Memory</p>
              <p className="text-lg font-semibold text-white">
                {metrics.memory.used_percent.toFixed(1)}%
              </p>
              <p className="text-xs text-slate-500">
                {formatBytes(metrics.memory.used_bytes)} / {formatBytes(metrics.memory.total_bytes)}
              </p>
            </div>
          </div>
        )}

        {/* Disk */}
        {metrics.disk && (
          <div className="flex items-start gap-2">
            <HardDrive className="h-4 w-4 text-blue-400 mt-1" />
            <div>
              <p className="text-xs text-slate-400">Disk</p>
              <p className="text-lg font-semibold text-white">
                {metrics.disk.used_percent.toFixed(1)}%
              </p>
              <p className="text-xs text-slate-500">
                {formatBytes(metrics.disk.used_bytes)} / {formatBytes(metrics.disk.total_bytes)}
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
