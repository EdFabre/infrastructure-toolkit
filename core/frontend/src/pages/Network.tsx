import React, { useState } from 'react';
import { useNetworkHealth, useNetworks, useWifiNetworks, useNetworkDevices, useNetworkClients } from '@/hooks/useNetwork';
import { StatusBadge } from '@/components/StatusBadge';
import { Wifi, Network as NetworkIcon, Users, Activity, Signal, Globe } from 'lucide-react';

export const Network: React.FC = () => {
  const { data: health, isLoading: healthLoading } = useNetworkHealth();
  const { data: networksData } = useNetworks();
  const { data: wifiData } = useWifiNetworks();
  const { data: devicesData } = useNetworkDevices();
  const { data: clientsData } = useNetworkClients({ top: 20, sortBy: 'traffic_down' });

  const [selectedTab, setSelectedTab] = useState<'overview' | 'wifi' | 'devices' | 'clients'>('overview');

  if (healthLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading network information...</p>
        </div>
      </div>
    );
  }

  const networks = networksData?.networks || [];
  const wlans = wifiData?.wlans || [];
  const devices = devicesData?.devices || [];
  const clients = clientsData?.clients || [];

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">
            Network Management
          </h1>
          <p className="text-slate-400">
            UniFi Dream Machine SE monitoring and configuration
          </p>
        </div>

        {/* Health Status */}
        {health && (
          <div className="card mb-8">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Globe className="h-8 w-8 text-primary-400" />
                <div>
                  <h2 className="text-xl font-semibold text-white">System Health</h2>
                  <p className="text-sm text-slate-400">UDM SE Status</p>
                </div>
              </div>
              <StatusBadge status={health.status} />
            </div>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="flex gap-2 mb-6">
          {[
            { id: 'overview', label: 'Overview', icon: NetworkIcon },
            { id: 'wifi', label: 'WiFi Networks', icon: Wifi },
            { id: 'devices', label: 'Devices', icon: Activity },
            { id: 'clients', label: 'Active Clients', icon: Users },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSelectedTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2 rounded-md transition-colors ${
                selectedTab === tab.id
                  ? 'bg-primary-600 text-white'
                  : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        {selectedTab === 'overview' && (
          <div className="space-y-6">
            {/* Networks */}
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-4">Networks</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {networks.map((network, idx) => (
                  <div key={idx} className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium text-white">{network.name}</h4>
                      <NetworkIcon className="h-5 w-5 text-primary-400" />
                    </div>
                    <p className="text-sm text-slate-400">VLAN {network.vlan}</p>
                    <p className="text-xs text-slate-500 mt-1">{network.subnet}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="card border border-primary-500/50">
                <div className="flex items-center gap-3">
                  <Wifi className="h-8 w-8 text-primary-400" />
                  <div>
                    <p className="text-2xl font-bold text-white">{wlans.length}</p>
                    <p className="text-sm text-slate-400">WiFi Networks</p>
                  </div>
                </div>
              </div>
              <div className="card border border-blue-500/50">
                <div className="flex items-center gap-3">
                  <Activity className="h-8 w-8 text-blue-400" />
                  <div>
                    <p className="text-2xl font-bold text-white">{devices.length}</p>
                    <p className="text-sm text-slate-400">Network Devices</p>
                  </div>
                </div>
              </div>
              <div className="card border border-green-500/50">
                <div className="flex items-center gap-3">
                  <Users className="h-8 w-8 text-green-400" />
                  <div>
                    <p className="text-2xl font-bold text-white">{clientsData?.total || 0}</p>
                    <p className="text-sm text-slate-400">Active Clients</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedTab === 'wifi' && (
          <div className="card">
            <h3 className="text-lg font-semibold text-white mb-4">WiFi Networks</h3>
            <div className="space-y-3">
              {wlans.map((wlan, idx) => (
                <div key={idx} className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Wifi className="h-5 w-5 text-primary-400" />
                      <div>
                        <h4 className="font-medium text-white">{wlan.name}</h4>
                        <p className="text-sm text-slate-400">SSID: {wlan.ssid}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <p className="text-xs text-slate-500">Security</p>
                        <p className="text-sm text-white">{wlan.security}</p>
                      </div>
                      <StatusBadge status={wlan.enabled ? 'healthy' : 'warning'} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {selectedTab === 'devices' && (
          <div className="card">
            <h3 className="text-lg font-semibold text-white mb-4">Network Devices</h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {devices.map((device, idx) => (
                <div key={idx} className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <Activity className="h-5 w-5 text-blue-400" />
                      <div>
                        <h4 className="font-medium text-white">{device.name}</h4>
                        <p className="text-xs text-slate-500">{device.model}</p>
                      </div>
                    </div>
                    <StatusBadge status={device.state === 1 ? 'healthy' : 'critical'} />
                  </div>
                  <div className="mt-2 text-xs text-slate-400">
                    <p>IP: {device.ip}</p>
                    <p>MAC: {device.mac}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {selectedTab === 'clients' && (
          <div className="card">
            <h3 className="text-lg font-semibold text-white mb-4">
              Active Clients (Top {clients.length} by Traffic)
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-3 px-4 text-slate-400 font-medium">Hostname</th>
                    <th className="text-left py-3 px-4 text-slate-400 font-medium">IP</th>
                    <th className="text-left py-3 px-4 text-slate-400 font-medium">Network</th>
                    <th className="text-right py-3 px-4 text-slate-400 font-medium">Download</th>
                    <th className="text-right py-3 px-4 text-slate-400 font-medium">Upload</th>
                    <th className="text-center py-3 px-4 text-slate-400 font-medium">Signal</th>
                  </tr>
                </thead>
                <tbody>
                  {clients.map((client, idx) => (
                    <tr key={idx} className="border-b border-slate-800 hover:bg-slate-700/30">
                      <td className="py-3 px-4 text-white">{client.hostname || 'Unknown'}</td>
                      <td className="py-3 px-4 text-slate-400">{client.ip}</td>
                      <td className="py-3 px-4 text-slate-400">{client.network || 'N/A'}</td>
                      <td className="py-3 px-4 text-right text-green-400">
                        {((client.rx_bytes || 0) / 1024 / 1024).toFixed(2)} MB
                      </td>
                      <td className="py-3 px-4 text-right text-blue-400">
                        {((client.tx_bytes || 0) / 1024 / 1024).toFixed(2)} MB
                      </td>
                      <td className="py-3 px-4 text-center">
                        {client.signal ? (
                          <div className="flex items-center justify-center gap-1">
                            <Signal className="h-4 w-4 text-primary-400" />
                            <span className="text-white">{client.signal} dBm</span>
                          </div>
                        ) : (
                          <span className="text-slate-500">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
