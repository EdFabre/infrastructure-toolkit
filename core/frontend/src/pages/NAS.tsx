import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/services/api';
import {
  Activity,
  Database,
  AlertCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  XCircle,
  Clock,
  Disc,
  FolderTree,
  Settings
} from 'lucide-react';

export const NAS: React.FC = () => {
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});

  const { data: nasData, isLoading, error } = useQuery({
    queryKey: ['nas', 'systems'],
    queryFn: () => apiClient.getNASSystems(),
    refetchInterval: 30000,
  });

  // Unraid-specific queries
  const { data: unraidParityData } = useQuery({
    queryKey: ['nas', 'unraid', 'parity'],
    queryFn: async () => {
      const response = await fetch('http://192.168.1.10:8001/api/nas/unraid/parity-status');
      return response.json();
    },
    refetchInterval: 30000,
    enabled: expandedSections['unraid-parity'],
  });

  const { data: unraidDiskData } = useQuery({
    queryKey: ['nas', 'unraid', 'disks'],
    queryFn: async () => {
      const response = await fetch('http://192.168.1.10:8001/api/nas/unraid/disk-status');
      return response.json();
    },
    refetchInterval: 30000,
    enabled: expandedSections['unraid-disks'],
  });

  // TrueNAS-specific queries
  const { data: truenasScrubData } = useQuery({
    queryKey: ['nas', 'truenas', 'scrub'],
    queryFn: async () => {
      const response = await fetch('http://192.168.1.10:8001/api/nas/truenas/scrub-status');
      return response.json();
    },
    refetchInterval: 30000,
    enabled: expandedSections['truenas-scrub'],
  });

  const { data: truenasDatasets } = useQuery({
    queryKey: ['nas', 'truenas', 'datasets'],
    queryFn: async () => {
      const response = await fetch('http://192.168.1.10:8001/api/nas/truenas/datasets');
      return response.json();
    },
    refetchInterval: 30000,
    enabled: expandedSections['truenas-datasets'],
  });

  const { data: truenasServices } = useQuery({
    queryKey: ['nas', 'truenas', 'services'],
    queryFn: async () => {
      const response = await fetch('http://192.168.1.10:8001/api/nas/truenas/services');
      return response.json();
    },
    refetchInterval: 30000,
    enabled: expandedSections['truenas-services'],
  });

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const nasServers = nasData?.systems || [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading NAS information...</p>
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
            Error Loading NAS Data
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
            NAS Storage Systems
          </h1>
          <p className="text-slate-400">
            Monitor and manage UnRAID and TrueNAS storage infrastructure
          </p>
        </div>

        {/* NAS Systems Grid */}
        <div className="grid grid-cols-1 gap-6 mb-8">
          {nasServers.map((nas) => {
            const color = nas.type === 'unraid' ? 'orange' : 'blue';
            const isHealthy = nas.status === 'healthy';
            const isDegraded = nas.status === 'degraded';
            const isUnraid = nas.type === 'unraid';
            const isTrueNAS = nas.type === 'truenas';

            return (
              <div key={nas.name} className={`card border ${
                isDegraded ? 'border-yellow-500/50' :
                isHealthy ? `border-${color}-500/50` : 'border-red-500/50'
              }`}>
                {/* Header */}
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <Database className={`h-8 w-8 ${
                      isDegraded ? 'text-yellow-400' :
                      isHealthy ? `text-${color}-400` : 'text-red-400'
                    }`} />
                    <div>
                      <h2 className="text-xl font-semibold text-white">{nas.name}</h2>
                      <p className="text-sm text-slate-400">{nas.ip}</p>
                    </div>
                  </div>
                  <div>
                    {isDegraded && (
                      <div className="px-3 py-1 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400 border border-yellow-500/50 mb-1">
                        <AlertTriangle className="inline h-3 w-3 mr-1" />
                        Degraded
                      </div>
                    )}
                    <div className={`px-3 py-1 rounded-full text-xs font-medium ${
                      nas.reachable
                        ? 'bg-green-500/20 text-green-400 border border-green-500/50'
                        : 'bg-red-500/20 text-red-400 border border-red-500/50'
                    }`}>
                      {nas.reachable ? '● Online' : '● Offline'}
                    </div>
                  </div>
                </div>

                {/* Basic Info */}
                <div className="space-y-4">
                  <div>
                    <p className="text-sm text-slate-400 mb-2">Purpose</p>
                    <p className="text-white">{nas.purpose}</p>
                  </div>

                  {nas.issues && (
                    <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-md">
                      <p className="text-sm text-yellow-400">{nas.issues}</p>
                    </div>
                  )}

                  {nas.uptime && (
                    <div>
                      <p className="text-sm text-slate-400 mb-1">Uptime & Load</p>
                      <p className="text-xs text-slate-300 font-mono">{nas.uptime}</p>
                    </div>
                  )}

                  {/* Metrics Grid */}
                  <div className="grid grid-cols-3 gap-4 pt-4 border-t border-slate-700">
                    {nas.storage && (
                      <div>
                        <p className="text-xs text-slate-400 mb-1">Storage</p>
                        <p className="text-sm text-white font-medium">
                          {nas.storage.used} / {nas.storage.total}
                        </p>
                        <div className="w-full bg-slate-700 rounded-full h-1.5 mt-2">
                          <div
                            className="bg-blue-500 h-1.5 rounded-full"
                            style={{width: `${nas.storage.used_percent}%`}}
                          ></div>
                        </div>
                        <p className="text-xs text-slate-500 mt-1">{nas.storage.used_percent}% used</p>
                      </div>
                    )}

                    {nas.memory && (
                      <div>
                        <p className="text-xs text-slate-400 mb-1">Memory</p>
                        <p className="text-sm text-white font-medium">
                          {nas.memory.used || `${nas.memory.total_gb?.toFixed(1)} GB`}
                        </p>
                        <p className="text-xs text-slate-500">
                          {nas.memory.total || `${nas.memory.total_gb?.toFixed(1)} GB total`}
                        </p>
                      </div>
                    )}

                    {nas.pools && (
                      <div>
                        <p className="text-xs text-slate-400 mb-1">ZFS Pools</p>
                        <p className="text-sm text-white font-medium">{nas.pools.length} pools</p>
                        <p className="text-xs text-slate-500">
                          {nas.pools.filter((p: any) => p.health === 'ONLINE').length} online
                        </p>
                      </div>
                    )}

                    {nas.array && (
                      <div>
                        <p className="text-xs text-slate-400 mb-1">Array</p>
                        <p className="text-sm text-white font-medium">{nas.array.mdState}</p>
                        <p className="text-xs text-slate-500">
                          {nas.array.mdNumDisks} disks
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Pool Status (Basic) */}
                  {nas.pools && nas.pools.length > 0 && (
                    <div className="pt-4 border-t border-slate-700">
                      <p className="text-sm text-slate-400 mb-2">Pool Status</p>
                      <div className="space-y-2">
                        {nas.pools.map((pool: any) => (
                          <div key={pool.name} className="flex items-center justify-between text-xs">
                            <div className="flex items-center gap-2">
                              <span className="text-slate-300">{pool.name}</span>
                              <span className={`px-2 py-0.5 rounded text-xs ${
                                pool.health === 'ONLINE' ? 'bg-green-500/20 text-green-400' :
                                pool.health === 'DEGRADED' ? 'bg-yellow-500/20 text-yellow-400' :
                                'bg-red-500/20 text-red-400'
                              }`}>
                                {pool.health}
                              </span>
                            </div>
                            <span className="text-slate-500">{pool.cap} used</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Unraid-Specific Expandable Sections */}
                {isUnraid && (
                  <div className="mt-6 space-y-3">
                    {/* Parity Check Status */}
                    <div className="border border-slate-700 rounded-md overflow-hidden">
                      <button
                        onClick={() => toggleSection('unraid-parity')}
                        className="w-full px-4 py-3 bg-slate-800/50 hover:bg-slate-800 transition-colors flex items-center justify-between"
                      >
                        <div className="flex items-center gap-2">
                          <CheckCircle className="h-4 w-4 text-orange-400" />
                          <span className="text-sm font-medium text-white">Parity Check Status</span>
                        </div>
                        {expandedSections['unraid-parity'] ? (
                          <ChevronUp className="h-4 w-4 text-slate-400" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-slate-400" />
                        )}
                      </button>

                      {expandedSections['unraid-parity'] && unraidParityData && (
                        <div className="p-4 space-y-3">
                          {unraidParityData.parity_check_running ? (
                            <>
                              <div className="flex items-center gap-2 text-blue-400">
                                <Clock className="h-4 w-4 animate-spin" />
                                <span className="text-sm font-medium">Parity check in progress</span>
                              </div>
                              {unraidParityData.progress_percent && (
                                <div>
                                  <div className="flex justify-between text-xs text-slate-400 mb-1">
                                    <span>Progress</span>
                                    <span>{unraidParityData.progress_percent.toFixed(2)}%</span>
                                  </div>
                                  <div className="w-full bg-slate-700 rounded-full h-2">
                                    <div
                                      className="bg-blue-500 h-2 rounded-full transition-all"
                                      style={{width: `${unraidParityData.progress_percent}%`}}
                                    ></div>
                                  </div>
                                  {unraidParityData.estimated_finish && (
                                    <p className="text-xs text-slate-500 mt-1">
                                      Estimated finish: {unraidParityData.estimated_finish}
                                    </p>
                                  )}
                                </div>
                              )}
                            </>
                          ) : (
                            <div className="flex items-center gap-2 text-green-400">
                              <CheckCircle className="h-4 w-4" />
                              <span className="text-sm">No parity check running</span>
                            </div>
                          )}
                          {unraidParityData.last_check_log && (
                            <div className="mt-3 p-2 bg-slate-800/50 rounded text-xs text-slate-400 font-mono">
                              {unraidParityData.last_check_log}
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Disk Status */}
                    <div className="border border-slate-700 rounded-md overflow-hidden">
                      <button
                        onClick={() => toggleSection('unraid-disks')}
                        className="w-full px-4 py-3 bg-slate-800/50 hover:bg-slate-800 transition-colors flex items-center justify-between"
                      >
                        <div className="flex items-center gap-2">
                          <Disc className="h-4 w-4 text-orange-400" />
                          <span className="text-sm font-medium text-white">Disk Spin Status</span>
                        </div>
                        {expandedSections['unraid-disks'] ? (
                          <ChevronUp className="h-4 w-4 text-slate-400" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-slate-400" />
                        )}
                      </button>

                      {expandedSections['unraid-disks'] && unraidDiskData && (
                        <div className="p-4">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                            {unraidDiskData.disks?.map((disk: any) => (
                              <div key={disk.device} className="p-3 bg-slate-800/50 rounded-md">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-medium text-slate-300">{disk.device}</span>
                                  <div className={`h-2 w-2 rounded-full ${
                                    disk.state === 'active' ? 'bg-green-500' :
                                    disk.state === 'standby' ? 'bg-yellow-500' :
                                    'bg-slate-500'
                                  }`}></div>
                                </div>
                                <span className={`text-xs ${
                                  disk.state === 'active' ? 'text-green-400' :
                                  disk.state === 'standby' ? 'text-yellow-400' :
                                  'text-slate-500'
                                }`}>
                                  {disk.state}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* TrueNAS-Specific Expandable Sections */}
                {isTrueNAS && (
                  <div className="mt-6 space-y-3">
                    {/* Scrub Status */}
                    <div className="border border-slate-700 rounded-md overflow-hidden">
                      <button
                        onClick={() => toggleSection('truenas-scrub')}
                        className="w-full px-4 py-3 bg-slate-800/50 hover:bg-slate-800 transition-colors flex items-center justify-between"
                      >
                        <div className="flex items-center gap-2">
                          <Activity className="h-4 w-4 text-blue-400" />
                          <span className="text-sm font-medium text-white">Pool Scrub Status</span>
                        </div>
                        {expandedSections['truenas-scrub'] ? (
                          <ChevronUp className="h-4 w-4 text-slate-400" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-slate-400" />
                        )}
                      </button>

                      {expandedSections['truenas-scrub'] && truenasScrubData && (
                        <div className="p-4 space-y-4">
                          {truenasScrubData.pools?.map((pool: any) => (
                            <div key={pool.name} className="p-3 bg-slate-800/50 rounded-md">
                              <div className="flex items-center justify-between mb-2">
                                <span className="text-sm font-medium text-white">{pool.name}</span>
                                {pool.scrub_running && (
                                  <span className="text-xs px-2 py-1 bg-blue-500/20 text-blue-400 rounded">
                                    In Progress
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-slate-400">{pool.scrub_status}</p>
                              {pool.scrub_progress && (
                                <div className="mt-2">
                                  <div className="w-full bg-slate-700 rounded-full h-2">
                                    <div
                                      className="bg-blue-500 h-2 rounded-full"
                                      style={{width: `${pool.scrub_progress}%`}}
                                    ></div>
                                  </div>
                                  <p className="text-xs text-slate-500 mt-1">{pool.scrub_progress.toFixed(1)}%</p>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Datasets */}
                    <div className="border border-slate-700 rounded-md overflow-hidden">
                      <button
                        onClick={() => toggleSection('truenas-datasets')}
                        className="w-full px-4 py-3 bg-slate-800/50 hover:bg-slate-800 transition-colors flex items-center justify-between"
                      >
                        <div className="flex items-center gap-2">
                          <FolderTree className="h-4 w-4 text-blue-400" />
                          <span className="text-sm font-medium text-white">Datasets</span>
                        </div>
                        {expandedSections['truenas-datasets'] ? (
                          <ChevronUp className="h-4 w-4 text-slate-400" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-slate-400" />
                        )}
                      </button>

                      {expandedSections['truenas-datasets'] && truenasDatasets && (
                        <div className="p-4">
                          <div className="space-y-2 max-h-64 overflow-y-auto">
                            {truenasDatasets.datasets?.map((dataset: any) => (
                              <div key={dataset.name} className="p-2 bg-slate-800/50 rounded text-xs">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-slate-300 font-mono">{dataset.name}</span>
                                  <span className="text-slate-500">{dataset.used}</span>
                                </div>
                                <div className="flex items-center gap-2 text-slate-500">
                                  <span>Avail: {dataset.avail}</span>
                                  <span>•</span>
                                  <span>Refer: {dataset.refer}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Services */}
                    <div className="border border-slate-700 rounded-md overflow-hidden">
                      <button
                        onClick={() => toggleSection('truenas-services')}
                        className="w-full px-4 py-3 bg-slate-800/50 hover:bg-slate-800 transition-colors flex items-center justify-between"
                      >
                        <div className="flex items-center gap-2">
                          <Settings className="h-4 w-4 text-blue-400" />
                          <span className="text-sm font-medium text-white">Services</span>
                        </div>
                        {expandedSections['truenas-services'] ? (
                          <ChevronUp className="h-4 w-4 text-slate-400" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-slate-400" />
                        )}
                      </button>

                      {expandedSections['truenas-services'] && truenasServices && (
                        <div className="p-4">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                            {truenasServices.services?.map((service: any) => (
                              <div key={service.name} className="p-3 bg-slate-800/50 rounded-md">
                                <div className="flex items-center justify-between">
                                  <span className="text-xs font-medium text-slate-300 uppercase">{service.name}</span>
                                  {service.status === 'active' ? (
                                    <CheckCircle className="h-3 w-3 text-green-400" />
                                  ) : (
                                    <XCircle className="h-3 w-3 text-red-400" />
                                  )}
                                </div>
                                <span className={`text-xs ${
                                  service.status === 'active' ? 'text-green-400' : 'text-red-400'
                                }`}>
                                  {service.status}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
