import React, { useState, useEffect } from 'react';
import { AlertCircle, Bell, BellOff, X, CheckCircle, AlertTriangle } from 'lucide-react';
import type { ServerMetrics } from '@/types/api';

interface Alert {
  id: string;
  type: 'critical' | 'warning' | 'info';
  title: string;
  message: string;
  timestamp: Date;
  server?: string;
  acknowledged: boolean;
}

interface AlertSystemProps {
  servers: ServerMetrics[];
}

export const AlertSystem: React.FC<AlertSystemProps> = ({ servers }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isEnabled, setIsEnabled] = useState(true);
  const [showPanel, setShowPanel] = useState(false);
  const [playSound, setPlaySound] = useState(true);

  useEffect(() => {
    if (!servers || !isEnabled) return;

    const newAlerts: Alert[] = [];

    servers.forEach((server) => {
      // Critical: Server unreachable
      if (!server.reachable) {
        newAlerts.push({
          id: `unreachable-${server.server}`,
          type: 'critical',
          title: 'Server Unreachable',
          message: `${server.server} is not responding`,
          timestamp: new Date(),
          server: server.server,
          acknowledged: false,
        });
      }

      if (server.reachable && server.memory) {
        // Critical: Memory usage >= 90%
        if (server.memory.used_percent >= 90) {
          newAlerts.push({
            id: `memory-critical-${server.server}`,
            type: 'critical',
            title: 'Critical Memory Usage',
            message: `${server.server} memory at ${server.memory.used_percent.toFixed(1)}%`,
            timestamp: new Date(),
            server: server.server,
            acknowledged: false,
          });
        }
        // Warning: Memory usage >= 80%
        else if (server.memory.used_percent >= 80) {
          newAlerts.push({
            id: `memory-warning-${server.server}`,
            type: 'warning',
            title: 'High Memory Usage',
            message: `${server.server} memory at ${server.memory.used_percent.toFixed(1)}%`,
            timestamp: new Date(),
            server: server.server,
            acknowledged: false,
          });
        }
      }

      if (server.reachable && server.disk) {
        // Critical: Disk usage >= 90%
        if (server.disk.used_percent >= 90) {
          newAlerts.push({
            id: `disk-critical-${server.server}`,
            type: 'critical',
            title: 'Critical Disk Usage',
            message: `${server.server} disk at ${server.disk.used_percent.toFixed(1)}%`,
            timestamp: new Date(),
            server: server.server,
            acknowledged: false,
          });
        }
        // Warning: Disk usage >= 80%
        else if (server.disk.used_percent >= 80) {
          newAlerts.push({
            id: `disk-warning-${server.server}`,
            type: 'warning',
            title: 'High Disk Usage',
            message: `${server.server} disk at ${server.disk.used_percent.toFixed(1)}%`,
            timestamp: new Date(),
            server: server.server,
            acknowledged: false,
          });
        }
      }

      if (server.reachable && server.cpu_load) {
        // Warning: CPU load > 4 (for typical 4-core systems)
        if (server.cpu_load['1min'] > 4) {
          newAlerts.push({
            id: `cpu-warning-${server.server}`,
            type: 'warning',
            title: 'High CPU Load',
            message: `${server.server} CPU load at ${server.cpu_load['1min'].toFixed(2)}`,
            timestamp: new Date(),
            server: server.server,
            acknowledged: false,
          });
        }
      }
    });

    // Check for new critical alerts
    const hasNewCritical = newAlerts.some(
      (alert) =>
        alert.type === 'critical' &&
        !alerts.find((a) => a.id === alert.id && a.acknowledged)
    );

    if (hasNewCritical && playSound) {
      // Play alert sound (browser notification sound)
      const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBjGJ0fPTgjMGHm7A7+OZQA0PUrDp8KxnFw1Andfz0H8vBSp+zPLaizsIGGS56ueZVBALTKXh8bllHAU2jtHz0n8wBCh6yvHejz0JGmO46uidWBELTKXh8bllHAU2jtHz0n8wBCh6yvHejz0JGmO46uidWBELTKPh8bdlHAU2jtHz0n8wBCh6yvHejz0JGmO46uidWBELTKPh8bdlHAU2jtHz0n8wBCh6yvHejz0JGmO46uidWBELTKPh8bdlHAU2jtHz0n8wBCh6yvHejz0JGmO46uidWBELTKPh8bdlHAU2jtHz0n8wBCh6yvHejz0JGmO46uidWBELTKPh8bdlHAU2jtHz0n8wBCh6yvHejz0JGmO46uidWBELTKPh8bdlHAU2jtHz0n8wBCh6yvHejz0JGmO46uidWBELTKPh8bdlHAU2jtHz0n8wBCh6yvHejz0JGmO46uidWBELTKPh8bdlHAU2jtHz0n8wBCh6yvHe');
      audio.play().catch(() => {
        // Ignore audio errors (browser may block autoplay)
      });
    }

    // Merge with existing alerts, preserving acknowledged status
    setAlerts((prev) => {
      const merged = newAlerts.map((newAlert) => {
        const existing = prev.find((a) => a.id === newAlert.id);
        if (existing) {
          return { ...newAlert, acknowledged: existing.acknowledged };
        }
        return newAlert;
      });

      // Remove alerts that no longer exist
      return merged;
    });
  }, [servers, isEnabled, playSound]);

  const acknowledgeAlert = (id: string) => {
    setAlerts((prev) =>
      prev.map((alert) => (alert.id === id ? { ...alert, acknowledged: true } : alert))
    );
  };

  const acknowledgeAll = () => {
    setAlerts((prev) => prev.map((alert) => ({ ...alert, acknowledged: true })));
  };

  const clearAcknowledged = () => {
    setAlerts((prev) => prev.filter((alert) => !alert.acknowledged));
  };

  const unacknowledgedCount = alerts.filter((a) => !a.acknowledged).length;
  const criticalCount = alerts.filter((a) => a.type === 'critical' && !a.acknowledged).length;

  const getAlertIcon = (type: Alert['type']) => {
    switch (type) {
      case 'critical':
        return <AlertCircle className="h-5 w-5 text-red-400" />;
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-yellow-400" />;
      case 'info':
        return <CheckCircle className="h-5 w-5 text-blue-400" />;
    }
  };

  const getAlertColor = (type: Alert['type']) => {
    switch (type) {
      case 'critical':
        return 'border-red-500/50 bg-red-500/10';
      case 'warning':
        return 'border-yellow-500/50 bg-yellow-500/10';
      case 'info':
        return 'border-blue-500/50 bg-blue-500/10';
    }
  };

  return (
    <>
      {/* Alert Bell Button */}
      <div className="fixed bottom-6 right-6 z-50">
        <button
          onClick={() => setShowPanel(!showPanel)}
          className="relative p-4 bg-slate-800 hover:bg-slate-700 rounded-full shadow-lg border border-slate-600 transition-colors"
        >
          {isEnabled ? (
            <Bell className="h-6 w-6 text-white" />
          ) : (
            <BellOff className="h-6 w-6 text-slate-400" />
          )}
          {unacknowledgedCount > 0 && (
            <span className={`absolute -top-1 -right-1 h-6 w-6 rounded-full flex items-center justify-center text-xs font-bold text-white ${criticalCount > 0 ? 'bg-red-500 animate-pulse' : 'bg-yellow-500'}`}>
              {unacknowledgedCount}
            </span>
          )}
        </button>
      </div>

      {/* Alert Panel */}
      {showPanel && (
        <div className="fixed bottom-24 right-6 w-96 max-h-[600px] bg-slate-800 rounded-lg shadow-2xl border border-slate-600 z-50 overflow-hidden flex flex-col">
          {/* Header */}
          <div className="p-4 border-b border-slate-600">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-lg font-semibold text-white">Alerts</h3>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setIsEnabled(!isEnabled)}
                  className="p-1.5 hover:bg-slate-700 rounded transition-colors"
                  title={isEnabled ? 'Disable alerts' : 'Enable alerts'}
                >
                  {isEnabled ? (
                    <Bell className="h-4 w-4 text-white" />
                  ) : (
                    <BellOff className="h-4 w-4 text-slate-400" />
                  )}
                </button>
                <button
                  onClick={() => setShowPanel(false)}
                  className="p-1.5 hover:bg-slate-700 rounded transition-colors"
                >
                  <X className="h-4 w-4 text-white" />
                </button>
              </div>
            </div>

            {unacknowledgedCount > 0 && (
              <div className="flex gap-2">
                <button
                  onClick={acknowledgeAll}
                  className="flex-1 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded transition-colors"
                >
                  Acknowledge All
                </button>
                <button
                  onClick={clearAcknowledged}
                  className="flex-1 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded transition-colors"
                >
                  Clear Read
                </button>
              </div>
            )}
          </div>

          {/* Alerts List */}
          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {alerts.length === 0 ? (
              <div className="text-center py-8 text-slate-400">
                <CheckCircle className="h-12 w-12 mx-auto mb-2 text-green-400" />
                <p>No active alerts</p>
              </div>
            ) : (
              alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`p-3 rounded-lg border ${getAlertColor(alert.type)} ${alert.acknowledged ? 'opacity-50' : ''}`}
                >
                  <div className="flex items-start gap-3">
                    {getAlertIcon(alert.type)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <h4 className="font-medium text-white text-sm truncate">
                          {alert.title}
                        </h4>
                        {!alert.acknowledged && (
                          <button
                            onClick={() => acknowledgeAlert(alert.id)}
                            className="px-2 py-0.5 bg-slate-700 hover:bg-slate-600 text-xs text-white rounded transition-colors shrink-0"
                          >
                            Ack
                          </button>
                        )}
                      </div>
                      <p className="text-sm text-slate-300">{alert.message}</p>
                      <p className="text-xs text-slate-500 mt-1">
                        {alert.timestamp.toLocaleTimeString()}
                      </p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </>
  );
};
