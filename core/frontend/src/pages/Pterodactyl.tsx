import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/services/api';
import { StatusBadge } from '@/components/StatusBadge';
import { Gamepad2, Server, HardDrive, AlertTriangle, CheckCircle, AlertCircle } from 'lucide-react';

export const Pterodactyl: React.FC = () => {
  const { data: nodesData, isLoading, error } = useQuery({
    queryKey: ['pterodactyl', 'nodes'],
    queryFn: () => apiClient.getPterodactylNodes(),
    refetchInterval: 30000,
  });

  const { data: diagnosis } = useQuery({
    queryKey: ['pterodactyl', 'diagnosis'],
    queryFn: () => apiClient.diagnosePterodactyl(),
    refetchInterval: 60000,
  });

  const nodes = nodesData?.nodes || [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading Pterodactyl information...</p>
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
            Error Loading Pterodactyl Data
          </h2>
          <p className="text-slate-400 text-center">
            {error instanceof Error ? error.message : 'Unknown error occurred'}
          </p>
        </div>
      </div>
    );
  }

  const totalMemory = nodes.reduce((acc, node) => acc + (node.memory || 0), 0);
  // const totalDisk = nodes.reduce((acc, node) => acc + (node.disk || 0), 0);
  const allocatedMemory = nodes.reduce((acc, node) => acc + (node.allocated_memory || 0), 0);

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">
            Pterodactyl Game Server Panel
          </h1>
          <p className="text-slate-400">
            Monitor game server nodes and diagnose issues
          </p>
        </div>

        {/* Diagnosis Alert */}
        {diagnosis && diagnosis.issues && diagnosis.issues.length > 0 && (
          <div className="card border border-yellow-500/50 mb-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-6 w-6 text-yellow-400 mt-1" />
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-white mb-2">
                  Configuration Issues Detected
                </h3>
                <div className="space-y-3">
                  {diagnosis.issues.map((issue, idx) => (
                    <div key={idx} className="bg-slate-800/50 rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2">
                        <h4 className="font-medium text-yellow-400">{issue.node}</h4>
                        <span className="text-xs text-slate-500">{issue.issue}</span>
                      </div>
                      <p className="text-sm text-slate-300 mb-2">
                        <strong>Current:</strong> {issue.current}
                      </p>
                      <p className="text-sm text-slate-300 mb-2">
                        <strong>Expected:</strong> {issue.expected}
                      </p>
                      <p className="text-sm text-red-400 mb-3">
                        <strong>Impact:</strong> {issue.impact}
                      </p>
                      <div className="bg-slate-900 rounded p-3 border border-slate-700">
                        <p className="text-xs text-slate-400 mb-1">Fix:</p>
                        <code className="text-xs text-green-400">{issue.fix}</code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {diagnosis && (!diagnosis.issues || diagnosis.issues.length === 0) && (
          <div className="card border border-green-500/50 mb-6">
            <div className="flex items-center gap-3">
              <CheckCircle className="h-8 w-8 text-green-400" />
              <div>
                <h3 className="text-lg font-semibold text-white">All Systems Healthy</h3>
                <p className="text-sm text-slate-400">No configuration issues detected</p>
              </div>
            </div>
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="card border border-primary-500/50">
            <div className="flex items-center gap-3">
              <Server className="h-8 w-8 text-primary-400" />
              <div>
                <p className="text-2xl font-bold text-white">{nodes.length}</p>
                <p className="text-sm text-slate-400">Game Server Nodes</p>
              </div>
            </div>
          </div>
          <div className="card border border-blue-500/50">
            <div className="flex items-center gap-3">
              <HardDrive className="h-8 w-8 text-blue-400" />
              <div>
                <p className="text-2xl font-bold text-white">
                  {(allocatedMemory / 1024).toFixed(0)} GB
                </p>
                <p className="text-sm text-slate-400">
                  Allocated / {(totalMemory / 1024).toFixed(0)} GB Total
                </p>
              </div>
            </div>
          </div>
          <div className="card border border-green-500/50">
            <div className="flex items-center gap-3">
              <Gamepad2 className="h-8 w-8 text-green-400" />
              <div>
                <p className="text-2xl font-bold text-white">
                  {((allocatedMemory / totalMemory) * 100).toFixed(0)}%
                </p>
                <p className="text-sm text-slate-400">Memory Utilization</p>
              </div>
            </div>
          </div>
        </div>

        {/* Nodes List */}
        <div className="card">
          <h2 className="text-xl font-semibold text-white mb-4">Wings Nodes</h2>
          <div className="space-y-4">
            {nodes.map((node) => (
              <div
                key={node.id}
                className="bg-slate-700/50 rounded-lg p-4 border border-slate-600"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <Server className="h-6 w-6 text-primary-400" />
                    <div>
                      <h3 className="text-lg font-semibold text-white">{node.name}</h3>
                      <p className="text-sm text-slate-400">{node.fqdn}</p>
                    </div>
                  </div>
                  <StatusBadge
                    status={node.daemon_listen === 8080 || node.daemon_listen === 48080 ? 'healthy' : 'warning'}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-4">
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Daemon Port</p>
                    <p className="text-white font-medium">{node.daemon_listen}</p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Scheme</p>
                    <p className="text-white font-medium">{node.scheme}</p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Memory</p>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-slate-800 rounded-full h-2">
                        <div
                          className="bg-blue-500 h-2 rounded-full"
                          style={{
                            width: `${((node.allocated_memory || 0) / (node.memory || 1)) * 100}%`
                          }}
                        />
                      </div>
                      <span className="text-white text-xs">
                        {((node.allocated_memory || 0) / 1024).toFixed(0)} GB
                      </span>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Disk</p>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-slate-800 rounded-full h-2">
                        <div
                          className="bg-green-500 h-2 rounded-full"
                          style={{
                            width: `${((node.allocated_disk || 0) / (node.disk || 1)) * 100}%`
                          }}
                        />
                      </div>
                      <span className="text-white text-xs">
                        {((node.allocated_disk || 0) / 1024).toFixed(0)} GB
                      </span>
                    </div>
                  </div>
                </div>

                {node.description && (
                  <p className="text-sm text-slate-400 mt-3 pt-3 border-t border-slate-700">
                    {node.description}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>

        {nodes.length === 0 && (
          <div className="card text-center py-12">
            <Gamepad2 className="h-16 w-16 text-slate-600 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No Nodes Found</h3>
            <p className="text-slate-400">
              No Pterodactyl wings nodes are currently configured
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
