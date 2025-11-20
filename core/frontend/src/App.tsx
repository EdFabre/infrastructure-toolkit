import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Dashboard } from '@/pages/Dashboard';
import { Logs } from '@/pages/Logs';
import { Network } from '@/pages/Network';
import { Docker } from '@/pages/Docker';
import { Cloudflare } from '@/pages/Cloudflare';
import { Pterodactyl } from '@/pages/Pterodactyl';
import { LayoutDashboard, FileText, Wifi, Container, Cloud, Gamepad2 } from 'lucide-react';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function Navigation() {
  const location = useLocation();

  const isActive = (path: string) => location.pathname === path;

  const navItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/network', label: 'Network', icon: Wifi },
    { path: '/docker', label: 'Docker', icon: Container },
    { path: '/cloudflare', label: 'Cloudflare', icon: Cloud },
    { path: '/pterodactyl', label: 'Game Servers', icon: Gamepad2 },
    { path: '/logs', label: 'Logs', icon: FileText },
  ];

  return (
    <nav className="bg-slate-800 border-b border-slate-700">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-8">
            <h1 className="text-xl font-bold text-white">Infrastructure Toolkit</h1>
            <div className="flex gap-2">
              {navItems.map(({ path, label, icon: Icon }) => (
                <Link
                  key={path}
                  to={path}
                  className={`flex items-center gap-2 px-4 py-2 rounded-md transition-colors ${
                    isActive(path)
                      ? 'bg-primary-600 text-white'
                      : 'text-slate-400 hover:text-white hover:bg-slate-700'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {label}
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Navigation />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/network" element={<Network />} />
          <Route path="/docker" element={<Docker />} />
          <Route path="/cloudflare" element={<Cloudflare />} />
          <Route path="/pterodactyl" element={<Pterodactyl />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
