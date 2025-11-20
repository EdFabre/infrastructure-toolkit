import React, { useState, useEffect } from 'react';
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import type { ServerMetrics } from '@/types/api';

interface MetricsChartProps {
  servers: ServerMetrics[];
  metric: 'cpu' | 'memory' | 'disk';
}

interface ChartData {
  server: string;
  value: number;
  status: string;
}

export const MetricsChart: React.FC<MetricsChartProps> = ({ servers, metric }) => {
  const [chartData, setChartData] = useState<ChartData[]>([]);

  useEffect(() => {
    const data = servers
      .filter(s => s.reachable)
      .map(server => {
        let value = 0;

        switch (metric) {
          case 'cpu':
            value = server.cpu_load?.['1min'] || 0;
            break;
          case 'memory':
            value = server.memory?.used_percent || 0;
            break;
          case 'disk':
            value = server.disk?.used_percent || 0;
            break;
        }

        return {
          server: server.server,
          value: Number(value.toFixed(2)),
          status: server.status,
        };
      })
      .sort((a, b) => a.server.localeCompare(b.server));

    setChartData(data);
  }, [servers, metric]);

  const getBarColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return '#10b981'; // green-500
      case 'warning':
        return '#f59e0b'; // yellow-500
      case 'critical':
        return '#ef4444'; // red-500
      default:
        return '#6b7280'; // gray-500
    }
  };

  const getMetricLabel = () => {
    switch (metric) {
      case 'cpu':
        return 'CPU Load (1min)';
      case 'memory':
        return 'Memory Usage (%)';
      case 'disk':
        return 'Disk Usage (%)';
    }
  };

  const getYAxisDomain = () => {
    if (metric === 'cpu') {
      return [0, 'auto'];
    }
    return [0, 100];
  };

  return (
    <div className="card">
      <h3 className="text-lg font-semibold text-white mb-4">{getMetricLabel()}</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis
            dataKey="server"
            stroke="#9ca3af"
            tick={{ fill: '#9ca3af' }}
            angle={-45}
            textAnchor="end"
            height={80}
          />
          <YAxis
            stroke="#9ca3af"
            tick={{ fill: '#9ca3af' }}
            domain={getYAxisDomain()}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #475569',
              borderRadius: '0.5rem',
              color: '#f1f5f9',
            }}
            formatter={(value: number) => [
              metric === 'cpu' ? value.toFixed(2) : `${value.toFixed(1)}%`,
              getMetricLabel(),
            ]}
          />
          <Bar
            dataKey="value"
            fill="#3b82f6"
            radius={[4, 4, 0, 0]}
          >
            {chartData.map((entry, index) => (
              <rect key={`bar-${index}`} fill={getBarColor(entry.status)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

interface HistoricalMetricsProps {
  history: Array<{
    timestamp: string;
    cpu: number;
    memory: number;
    disk: number;
  }>;
}

export const HistoricalMetrics: React.FC<HistoricalMetricsProps> = ({ history }) => {
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="card">
      <h3 className="text-lg font-semibold text-white mb-4">Historical Metrics</h3>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={history}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis
            dataKey="timestamp"
            stroke="#9ca3af"
            tick={{ fill: '#9ca3af' }}
            tickFormatter={formatTime}
          />
          <YAxis
            stroke="#9ca3af"
            tick={{ fill: '#9ca3af' }}
            domain={[0, 100]}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #475569',
              borderRadius: '0.5rem',
              color: '#f1f5f9',
            }}
            labelFormatter={(label) => `Time: ${formatTime(label)}`}
          />
          <Legend wrapperStyle={{ color: '#9ca3af' }} />
          <Line
            type="monotone"
            dataKey="cpu"
            stroke="#f59e0b"
            strokeWidth={2}
            dot={false}
            name="CPU Load"
          />
          <Line
            type="monotone"
            dataKey="memory"
            stroke="#10b981"
            strokeWidth={2}
            dot={false}
            name="Memory %"
          />
          <Line
            type="monotone"
            dataKey="disk"
            stroke="#3b82f6"
            strokeWidth={2}
            dot={false}
            name="Disk %"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

interface MetricGaugeProps {
  value: number;
  max: number;
  label: string;
  status: 'healthy' | 'warning' | 'critical';
}

export const MetricGauge: React.FC<MetricGaugeProps> = ({ value, max, label, status }) => {
  const percentage = (value / max) * 100;

  const getColor = () => {
    switch (status) {
      case 'healthy':
        return 'bg-green-500';
      case 'warning':
        return 'bg-yellow-500';
      case 'critical':
        return 'bg-red-500';
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm">
        <span className="text-slate-400">{label}</span>
        <span className="text-white font-medium">
          {value.toFixed(1)} / {max}
        </span>
      </div>
      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
        <div
          className={`h-full ${getColor()} transition-all duration-300`}
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>
    </div>
  );
};
