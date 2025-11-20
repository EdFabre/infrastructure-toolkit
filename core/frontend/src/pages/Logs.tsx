import React, { useState } from 'react';
import { LogViewer } from '@/components/LogViewer';
import { Server } from 'lucide-react';

const SERVERS = [
  'boss-0',
  'boss-01',
  'boss-02',
  'boss-03',
  'boss-04',
  'boss-05',
  'boss-06',
  'boss-07',
  'king-01',
];

export const Logs: React.FC = () => {
  const [selectedServer, setSelectedServer] = useState<string>(SERVERS[1]); // Default to boss-01

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">
            Container Logs
          </h1>
          <p className="text-slate-400">
            Real-time Docker container log streaming
          </p>
        </div>

        {/* Server Selection */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-slate-400 mb-2">
            Select Server
          </label>
          <div className="flex flex-wrap gap-2">
            {SERVERS.map((server) => (
              <button
                key={server}
                onClick={() => setSelectedServer(server)}
                className={`flex items-center gap-2 px-4 py-2 rounded-md transition-colors ${
                  selectedServer === server
                    ? 'bg-primary-600 text-white'
                    : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                }`}
              >
                <Server className="h-4 w-4" />
                {server}
              </button>
            ))}
          </div>
        </div>

        {/* Log Viewer */}
        <LogViewer server={selectedServer} />
      </div>
    </div>
  );
};
