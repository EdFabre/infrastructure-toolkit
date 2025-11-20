import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/services/api';
import { StatusBadge } from '@/components/StatusBadge';
import { Cloud, Globe, CheckCircle, AlertCircle, Lock } from 'lucide-react';

export const Cloudflare: React.FC = () => {
  const [selectedDomain, setSelectedDomain] = useState<'haymoed' | 'ramcyber'>('haymoed');

  const { data: hostnamesData, isLoading, error } = useQuery({
    queryKey: ['cloudflare', 'hostnames', selectedDomain],
    queryFn: () => apiClient.getCloudflareHostnames(selectedDomain),
    refetchInterval: 60000,
  });

  const { data: validation } = useQuery({
    queryKey: ['cloudflare', 'validation', selectedDomain],
    queryFn: () => apiClient.validateCloudflareConfig(selectedDomain),
    refetchInterval: 60000,
  });

  const hostnames = hostnamesData?.hostnames || [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading Cloudflare configuration...</p>
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
            Error Loading Cloudflare Data
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
            Cloudflare Tunnel Management
          </h1>
          <p className="text-slate-400">
            Monitor and manage Cloudflare Tunnel hostnames
          </p>
        </div>

        {/* Domain Selector */}
        <div className="flex gap-4 mb-6">
          <button
            onClick={() => setSelectedDomain('haymoed')}
            className={`flex items-center gap-2 px-6 py-3 rounded-lg transition-colors ${
              selectedDomain === 'haymoed'
                ? 'bg-primary-600 text-white'
                : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
            }`}
          >
            <Globe className="h-5 w-5" />
            haymoed.com
          </button>
          <button
            onClick={() => setSelectedDomain('ramcyber')}
            className={`flex items-center gap-2 px-6 py-3 rounded-lg transition-colors ${
              selectedDomain === 'ramcyber'
                ? 'bg-primary-600 text-white'
                : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
            }`}
          >
            <Globe className="h-5 w-5" />
            ramcyber.com
          </button>
        </div>

        {/* Validation Status */}
        {validation && (
          <div className={`card mb-6 ${
            validation.valid
              ? 'border border-green-500/50'
              : 'border border-yellow-500/50'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {validation.valid ? (
                  <CheckCircle className="h-8 w-8 text-green-400" />
                ) : (
                  <AlertCircle className="h-8 w-8 text-yellow-400" />
                )}
                <div>
                  <h2 className="text-xl font-semibold text-white">
                    Configuration Validation
                  </h2>
                  <p className="text-sm text-slate-400">
                    {validation.hostname_count} hostnames configured
                  </p>
                </div>
              </div>
              <StatusBadge status={validation.valid ? 'healthy' : 'warning'} />
            </div>
            {validation.issues && validation.issues.length > 0 && (
              <div className="mt-4 pt-4 border-t border-slate-700">
                <h3 className="text-sm font-medium text-yellow-400 mb-2">Issues Found:</h3>
                <ul className="space-y-1">
                  {validation.issues.map((issue, idx) => (
                    <li key={idx} className="text-sm text-slate-300">
                      • {issue}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="card border border-primary-500/50">
            <div className="flex items-center gap-3">
              <Cloud className="h-8 w-8 text-primary-400" />
              <div>
                <p className="text-2xl font-bold text-white">{hostnames.length}</p>
                <p className="text-sm text-slate-400">Total Hostnames</p>
              </div>
            </div>
          </div>
          <div className="card border border-green-500/50">
            <div className="flex items-center gap-3">
              <Globe className="h-8 w-8 text-green-400" />
              <div>
                <p className="text-2xl font-bold text-white">
                  {hostnames.filter(h => h.service.includes('http')).length}
                </p>
                <p className="text-sm text-slate-400">HTTP Services</p>
              </div>
            </div>
          </div>
          <div className="card border border-blue-500/50">
            <div className="flex items-center gap-3">
              <Lock className="h-8 w-8 text-blue-400" />
              <div>
                <p className="text-2xl font-bold text-white">
                  {hostnames.filter(h => h.service.includes('https')).length}
                </p>
                <p className="text-sm text-slate-400">HTTPS Services</p>
              </div>
            </div>
          </div>
        </div>

        {/* Hostnames Table */}
        <div className="card">
          <h2 className="text-xl font-semibold text-white mb-4">
            Configured Hostnames
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">Hostname</th>
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">Service</th>
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">Path</th>
                  <th className="text-center py-3 px-4 text-slate-400 font-medium">Protocol</th>
                </tr>
              </thead>
              <tbody>
                {hostnames.map((hostname, idx) => (
                  <tr key={idx} className="border-b border-slate-800 hover:bg-slate-700/30">
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <Globe className="h-4 w-4 text-primary-400" />
                        <span className="text-white font-medium">{hostname.hostname}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <code className="text-sm text-green-400 bg-slate-800 px-2 py-1 rounded">
                        {hostname.service}
                      </code>
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {hostname.path || '/'}
                    </td>
                    <td className="py-3 px-4 text-center">
                      {hostname.service.includes('https') ? (
                        <div className="flex items-center justify-center gap-1">
                          <Lock className="h-4 w-4 text-blue-400" />
                          <span className="text-blue-400 text-sm">HTTPS</span>
                        </div>
                      ) : (
                        <span className="text-slate-500 text-sm">HTTP</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {hostnames.length === 0 && (
          <div className="card text-center py-12">
            <Cloud className="h-16 w-16 text-slate-600 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No Hostnames Configured</h3>
            <p className="text-slate-400">
              No Cloudflare Tunnel hostnames found for {selectedDomain}.com
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
