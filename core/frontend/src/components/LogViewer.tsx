import React, { useState, useEffect, useRef } from 'react';
import { Search, Download, Filter, Play, Pause, Trash2 } from 'lucide-react';
import { useLogsWebSocket } from '@/hooks/useWebSocket';

interface LogViewerProps {
  server: string;
}

export const LogViewer: React.FC<LogViewerProps> = ({ server }) => {
  const { logs, containers, isConnected, getLogs, listContainers } = useLogsWebSocket(server);
  const [selectedContainer, setSelectedContainer] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterLevel, setFilterLevel] = useState<'all' | 'error' | 'warn' | 'info'>('all');
  const [autoScroll, setAutoScroll] = useState(true);
  const [tailLines, setTailLines] = useState(100);
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    listContainers();
  }, [listContainers]);

  useEffect(() => {
    if (selectedContainer) {
      getLogs(selectedContainer, tailLines);
    }
  }, [selectedContainer, tailLines, getLogs]);

  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const filterLogs = (logText: string): string[] => {
    if (!logText) return [];

    const lines = logText.split('\n').filter(line => line.trim());

    return lines.filter(line => {
      // Search filter
      if (searchTerm && !line.toLowerCase().includes(searchTerm.toLowerCase())) {
        return false;
      }

      // Level filter
      if (filterLevel !== 'all') {
        const lowerLine = line.toLowerCase();
        switch (filterLevel) {
          case 'error':
            return lowerLine.includes('error') || lowerLine.includes('err') || lowerLine.includes('fatal');
          case 'warn':
            return lowerLine.includes('warn') || lowerLine.includes('warning');
          case 'info':
            return lowerLine.includes('info');
        }
      }

      return true;
    });
  };

  const getLineColor = (line: string): string => {
    const lowerLine = line.toLowerCase();
    if (lowerLine.includes('error') || lowerLine.includes('fatal')) {
      return 'text-red-400';
    }
    if (lowerLine.includes('warn')) {
      return 'text-yellow-400';
    }
    if (lowerLine.includes('info')) {
      return 'text-blue-400';
    }
    return 'text-slate-300';
  };

  const downloadLogs = () => {
    const blob = new Blob([logs], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${server}-${selectedContainer}-${new Date().toISOString()}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const clearLogs = () => {
    if (selectedContainer) {
      getLogs(selectedContainer, 0);
    }
  };

  const filteredLines = filterLogs(logs);

  return (
    <div className="card space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">
          Container Logs - {server}
        </h3>
        <div className="flex items-center gap-2">
          {isConnected ? (
            <span className="px-2 py-1 text-xs bg-green-500/20 text-green-400 rounded-full border border-green-500/50">
              Connected
            </span>
          ) : (
            <span className="px-2 py-1 text-xs bg-red-500/20 text-red-400 rounded-full border border-red-500/50">
              Disconnected
            </span>
          )}
        </div>
      </div>

      {/* Controls */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Container Selection */}
        <div>
          <label className="block text-sm text-slate-400 mb-1">Container</label>
          <select
            value={selectedContainer}
            onChange={(e) => setSelectedContainer(e.target.value)}
            className="w-full bg-slate-700 text-white px-3 py-2 rounded-md border border-slate-600 focus:border-primary-500 focus:outline-none"
          >
            <option value="">Select container...</option>
            {containers.map((container) => (
              <option key={container.name} value={container.name}>
                {container.name}
              </option>
            ))}
          </select>
        </div>

        {/* Tail Lines */}
        <div>
          <label className="block text-sm text-slate-400 mb-1">Tail Lines</label>
          <select
            value={tailLines}
            onChange={(e) => setTailLines(Number(e.target.value))}
            className="w-full bg-slate-700 text-white px-3 py-2 rounded-md border border-slate-600 focus:border-primary-500 focus:outline-none"
          >
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
            <option value="500">500</option>
            <option value="1000">1000</option>
          </select>
        </div>

        {/* Level Filter */}
        <div>
          <label className="block text-sm text-slate-400 mb-1">Filter Level</label>
          <div className="flex gap-1">
            {(['all', 'error', 'warn', 'info'] as const).map((level) => (
              <button
                key={level}
                onClick={() => setFilterLevel(level)}
                className={`flex-1 px-2 py-2 text-xs rounded-md transition-colors ${
                  filterLevel === level
                    ? 'bg-primary-600 text-white'
                    : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                }`}
              >
                {level.charAt(0).toUpperCase() + level.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Search */}
        <div>
          <label className="block text-sm text-slate-400 mb-1">Search</label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search logs..."
              className="w-full bg-slate-700 text-white pl-10 pr-3 py-2 rounded-md border border-slate-600 focus:border-primary-500 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setAutoScroll(!autoScroll)}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white rounded-md transition-colors text-sm"
        >
          {autoScroll ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
          {autoScroll ? 'Pause' : 'Resume'}
        </button>
        <button
          onClick={downloadLogs}
          disabled={!logs}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-sm"
        >
          <Download className="h-4 w-4" />
          Download
        </button>
        <button
          onClick={clearLogs}
          disabled={!selectedContainer}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-sm"
        >
          <Trash2 className="h-4 w-4" />
          Clear
        </button>
        <div className="ml-auto text-sm text-slate-400">
          {filteredLines.length} / {logs.split('\n').filter(l => l.trim()).length} lines
        </div>
      </div>

      {/* Log Display */}
      <div
        ref={logContainerRef}
        className="bg-slate-950 rounded-md p-4 h-[600px] overflow-y-auto font-mono text-sm"
      >
        {filteredLines.length > 0 ? (
          filteredLines.map((line, index) => (
            <div key={index} className={`${getLineColor(line)} hover:bg-slate-800/50 px-2 -mx-2`}>
              <span className="text-slate-500 select-none mr-4">{index + 1}</span>
              {line}
            </div>
          ))
        ) : (
          <div className="text-center text-slate-500 py-8">
            {selectedContainer
              ? searchTerm || filterLevel !== 'all'
                ? 'No logs match your filters'
                : 'No logs available'
              : 'Select a container to view logs'}
          </div>
        )}
      </div>
    </div>
  );
};
