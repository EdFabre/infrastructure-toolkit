import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '@/services/api';
import { StatusBadge } from '@/components/StatusBadge';
import {
  Usb,
  Monitor,
  RefreshCw,
  Wrench,
  CheckCircle,
  AlertTriangle,
  AlertCircle,
  Zap,
  Loader2,
} from 'lucide-react';

const DEFAULT_VM_ID = 301;
const DEFAULT_HOST = 'pve3';

export const Proxmox: React.FC = () => {
  const [selectedVmId] = useState(DEFAULT_VM_ID);
  const [isResetting, setIsResetting] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // Fetch USB status
  const { data: usbStatus, isLoading, error, refetch } = useQuery({
    queryKey: ['proxmox', 'usb', selectedVmId],
    queryFn: () => apiClient.getUSBStatus(selectedVmId, DEFAULT_HOST),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Fetch Proxmox health
  const { data: health } = useQuery({
    queryKey: ['proxmox', 'health'],
    queryFn: () => apiClient.getProxmoxHealth(DEFAULT_HOST),
    refetchInterval: 60000,
  });

  // Reset USB device mutation
  const resetMutation = useMutation({
    mutationFn: ({ deviceId }: { deviceId: string }) =>
      apiClient.resetUSBDevice(selectedVmId, deviceId, DEFAULT_HOST),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxmox', 'usb'] });
      setIsResetting(null);
    },
    onError: () => {
      setIsResetting(null);
    },
  });

  // Auto-fix mutation
  const autoFixMutation = useMutation({
    mutationFn: () => apiClient.autoFixUSB(selectedVmId, DEFAULT_HOST),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxmox', 'usb'] });
    },
  });

  const handleResetDevice = async (deviceId: string) => {
    setIsResetting(deviceId);
    resetMutation.mutate({ deviceId });
  };

  const handleAutoFix = async () => {
    autoFixMutation.mutate();
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading USB device information...</p>
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
            Error Loading USB Data
          </h2>
          <p className="text-slate-400 text-center">
            {error instanceof Error ? error.message : 'Unknown error occurred'}
          </p>
          <button
            onClick={() => refetch()}
            className="mt-4 w-full bg-primary-600 hover:bg-primary-700 text-white py-2 px-4 rounded-md transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const devices = usbStatus?.devices || [];
  const issues = usbStatus?.issues || [];
  const isHealthy = usbStatus?.status === 'healthy';

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">
            Proxmox USB Management
          </h1>
          <p className="text-slate-400">
            Monitor and manage USB passthrough devices for VM {selectedVmId}
          </p>
        </div>

        {/* Health Status Banner */}
        {health && (
          <div className={`card border mb-6 ${
            health.status === 'healthy' ? 'border-green-500/50' : 'border-red-500/50'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {health.status === 'healthy' ? (
                  <CheckCircle className="h-8 w-8 text-green-400" />
                ) : (
                  <AlertCircle className="h-8 w-8 text-red-400" />
                )}
                <div>
                  <h3 className="text-lg font-semibold text-white">
                    {health.status === 'healthy' ? 'Proxmox Connection Healthy' : 'Connection Issues'}
                  </h3>
                  <p className="text-sm text-slate-400">
                    Host: {health.host} ({health.ip})
                  </p>
                </div>
              </div>
              <button
                onClick={() => refetch()}
                className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-md transition-colors"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </div>
        )}

        {/* Issues Alert */}
        {issues.length > 0 && (
          <div className="card border border-yellow-500/50 mb-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-6 w-6 text-yellow-400 mt-1" />
              <div className="flex-1">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-lg font-semibold text-white">
                    USB Issues Detected
                  </h3>
                  <button
                    onClick={handleAutoFix}
                    disabled={autoFixMutation.isPending}
                    className="flex items-center gap-2 px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-yellow-800 text-white rounded-md transition-colors"
                  >
                    {autoFixMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Wrench className="h-4 w-4" />
                    )}
                    Auto-Fix All
                  </button>
                </div>
                <div className="space-y-2">
                  {issues.map((issue, idx) => (
                    <div key={idx} className="bg-slate-800/50 rounded-lg p-3">
                      <div className="flex items-center justify-between">
                        <span className="text-yellow-400 font-medium">{issue.device_id}</span>
                        <span className="text-sm text-slate-400">{issue.product}</span>
                      </div>
                      <p className="text-sm text-red-400 mt-1">{issue.issue}</p>
                      <p className="text-xs text-slate-500">Expected: {issue.expected}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Auto-fix Result */}
        {autoFixMutation.isSuccess && autoFixMutation.data && (
          <div className={`card border mb-6 ${
            autoFixMutation.data.status === 'fixed' || autoFixMutation.data.status === 'no_action_needed'
              ? 'border-green-500/50'
              : 'border-yellow-500/50'
          }`}>
            <div className="flex items-center gap-3">
              {autoFixMutation.data.status === 'fixed' || autoFixMutation.data.status === 'no_action_needed' ? (
                <CheckCircle className="h-6 w-6 text-green-400" />
              ) : (
                <AlertTriangle className="h-6 w-6 text-yellow-400" />
              )}
              <div>
                <h3 className="font-semibold text-white">
                  {autoFixMutation.data.status === 'fixed' && 'All devices fixed!'}
                  {autoFixMutation.data.status === 'no_action_needed' && autoFixMutation.data.message}
                  {autoFixMutation.data.status === 'partial' && 'Some devices could not be fixed'}
                </h3>
                {autoFixMutation.data.fixed_devices && autoFixMutation.data.fixed_devices.length > 0 && (
                  <p className="text-sm text-green-400">
                    Fixed: {autoFixMutation.data.fixed_devices.join(', ')}
                  </p>
                )}
                {autoFixMutation.data.failed_devices && autoFixMutation.data.failed_devices.length > 0 && (
                  <p className="text-sm text-red-400">
                    Failed: {autoFixMutation.data.failed_devices.join(', ')}
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className={`card border ${isHealthy ? 'border-green-500/50' : 'border-red-500/50'}`}>
            <div className="flex items-center gap-3">
              <Usb className={`h-8 w-8 ${isHealthy ? 'text-green-400' : 'text-red-400'}`} />
              <div>
                <p className="text-2xl font-bold text-white">{devices.length}</p>
                <p className="text-sm text-slate-400">USB Devices</p>
              </div>
            </div>
          </div>
          <div className="card border border-blue-500/50">
            <div className="flex items-center gap-3">
              <CheckCircle className="h-8 w-8 text-blue-400" />
              <div>
                <p className="text-2xl font-bold text-white">{usbStatus?.healthy_devices || 0}</p>
                <p className="text-sm text-slate-400">Healthy</p>
              </div>
            </div>
          </div>
          <div className="card border border-yellow-500/50">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-8 w-8 text-yellow-400" />
              <div>
                <p className="text-2xl font-bold text-white">{usbStatus?.unhealthy_devices || 0}</p>
                <p className="text-sm text-slate-400">Issues</p>
              </div>
            </div>
          </div>
        </div>

        {/* USB Devices List */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold text-white">USB Devices</h2>
            <div className="flex items-center gap-2">
              <Monitor className="h-5 w-5 text-slate-400" />
              <span className="text-slate-400">VM {selectedVmId}</span>
            </div>
          </div>

          <div className="space-y-4">
            {devices.map((device) => (
              <div
                key={device.device_id}
                className={`bg-slate-700/50 rounded-lg p-4 border ${
                  device.is_healthy ? 'border-slate-600' : 'border-yellow-500/50'
                }`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <Usb className={`h-6 w-6 ${device.is_healthy ? 'text-primary-400' : 'text-yellow-400'}`} />
                    <div>
                      <h3 className="text-lg font-semibold text-white">{device.product_name}</h3>
                      <p className="text-sm text-slate-400">{device.device_id}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <StatusBadge status={device.is_healthy ? 'healthy' : 'warning'} />
                    <button
                      onClick={() => handleResetDevice(device.device_id)}
                      disabled={isResetting === device.device_id || resetMutation.isPending}
                      className="flex items-center gap-2 px-3 py-1 bg-slate-600 hover:bg-slate-500 disabled:bg-slate-700 text-white text-sm rounded-md transition-colors"
                      title="Reset USB device"
                    >
                      {isResetting === device.device_id ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Zap className="h-4 w-4" />
                      )}
                      Reset
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Speed</p>
                    <p className={`font-medium ${
                      device.speed.includes('1.5') ? 'text-yellow-400' : 'text-white'
                    }`}>
                      {device.speed}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Port</p>
                    <p className="text-white font-medium">{device.port}</p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Vendor ID</p>
                    <p className="text-white font-medium font-mono">{device.vendor_id || 'N/A'}</p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Product ID</p>
                    <p className="text-white font-medium font-mono">{device.product_id || 'N/A'}</p>
                  </div>
                </div>

                {!device.is_healthy && (
                  <div className="mt-3 pt-3 border-t border-slate-600">
                    <p className="text-sm text-yellow-400">
                      <AlertTriangle className="h-4 w-4 inline mr-1" />
                      Device may not be functioning correctly. Speed should be 12 Mb/s or higher.
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>

          {devices.length === 0 && (
            <div className="text-center py-12">
              <Usb className="h-16 w-16 text-slate-600 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No USB Devices Found</h3>
              <p className="text-slate-400">
                No USB devices are currently passed through to VM {selectedVmId}
              </p>
            </div>
          )}
        </div>

        {/* Info Card */}
        <div className="card mt-6 border border-slate-700">
          <h3 className="text-lg font-semibold text-white mb-3">About USB Passthrough</h3>
          <div className="text-sm text-slate-400 space-y-2">
            <p>
              <strong className="text-slate-300">Logitech Unifying Receiver:</strong> Should show 12 Mb/s speed.
              If it shows 1.5 Mb/s or "USB Host Device", the device needs to be reset.
            </p>
            <p>
              <strong className="text-slate-300">Auto-Fix:</strong> Removes and re-adds the USB device using the
              host port path method, which is more reliable than vendor/product ID matching.
            </p>
            <p>
              <strong className="text-slate-300">Monitoring:</strong> A cron job on pve3 checks USB health every
              5 minutes and auto-fixes if issues are detected.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
