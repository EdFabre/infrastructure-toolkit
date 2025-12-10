import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from '@/contexts/AuthContext';
import { Dashboard } from '@/pages/Dashboard';
import { Servers } from '@/pages/Servers';
import { Logs } from '@/pages/Logs';
import { Network } from '@/pages/Network';
import { Docker } from '@/pages/Docker';
import { Cloudflare } from '@/pages/Cloudflare';
import { Pterodactyl } from '@/pages/Pterodactyl';
import { Proxmox } from '@/pages/Proxmox';
import { NAS } from '@/pages/NAS';
import { Login } from '@/pages/Login';
import { Settings } from '@/pages/Settings';
import { ForgotPassword } from '@/pages/ForgotPassword';
import { ResetPassword } from '@/pages/ResetPassword';
import { EmailSettings } from '@/pages/EmailSettings';
import { LayoutDashboard, FileText, Wifi, Container, Cloud, Gamepad2, Menu, X, Server, Database, LogOut, Settings as SettingsIcon, Mail, Usb } from 'lucide-react';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function AuthenticatedApp() {
  const [sidebarCollapsed, setSidebarCollapsed] = React.useState(false);

  return (
    <BrowserRouter>
      <NavigationWithState
        sidebarCollapsed={sidebarCollapsed}
        setSidebarCollapsed={setSidebarCollapsed}
      />

      {/* Main Content Area */}
      <div
        className={`transition-all duration-300 pt-16 ${
          sidebarCollapsed ? 'md:pl-16' : 'md:pl-64'
        }`}
      >
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/servers" element={<Servers />} />
          <Route path="/nas" element={<NAS />} />
          <Route path="/network" element={<Network />} />
          <Route path="/docker" element={<Docker />} />
          <Route path="/cloudflare" element={<Cloudflare />} />
          <Route path="/pterodactyl" element={<Pterodactyl />} />
          <Route path="/proxmox" element={<Proxmox />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/email-settings" element={<EmailSettings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

function NavigationWithState({
  sidebarCollapsed,
  setSidebarCollapsed
}: {
  sidebarCollapsed: boolean;
  setSidebarCollapsed: (collapsed: boolean) => void;
}) {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);
  const { user, logout } = useAuth();

  const isActive = (path: string) => location.pathname === path;

  const navItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/servers', label: 'Servers', icon: Server },
    { path: '/nas', label: 'NAS', icon: Database },
    { path: '/network', label: 'Network', icon: Wifi },
    { path: '/docker', label: 'Docker', icon: Container },
    { path: '/cloudflare', label: 'Cloudflare', icon: Cloud },
    { path: '/pterodactyl', label: 'Game Servers', icon: Gamepad2 },
    { path: '/proxmox', label: 'USB', icon: Usb },
    { path: '/logs', label: 'Logs', icon: FileText },
    { path: '/settings', label: 'Settings', icon: SettingsIcon },
    ...(user?.role === 'admin' ? [{ path: '/email-settings', label: 'Email', icon: Mail }] : []),
  ];

  const handleLogout = async () => {
    await logout();
    setMobileMenuOpen(false);
  };

  return (
    <>
      {/* Top Bar */}
      <div className="fixed top-0 left-0 right-0 h-16 bg-slate-800 border-b border-slate-700 z-30">
        <div className="flex items-center justify-between h-full px-4">
          <div className="flex items-center gap-3">
            {/* Desktop Sidebar Toggle */}
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="hidden md:block p-2 rounded-md text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
              aria-label="Toggle sidebar"
            >
              <Menu className="h-5 w-5" />
            </button>

            {/* Mobile Menu Toggle */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 rounded-md text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>

            <h1 className="text-xl font-bold text-white">Infrastructure Toolkit</h1>
          </div>

          {/* User Info & Logout */}
          <div className="flex items-center gap-3">
            <div className="hidden sm:block text-sm text-slate-400">
              <span className="text-slate-500">Logged in as</span>{' '}
              <span className="text-white font-medium">{user?.username}</span>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-2 rounded-md text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
              title="Logout"
            >
              <LogOut className="h-4 w-4" />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>
      </div>

      {/* Desktop Sidebar */}
      <aside
        className={`hidden md:block fixed left-0 top-16 bottom-0 bg-slate-800 border-r border-slate-700 transition-all duration-300 z-20 ${
          sidebarCollapsed ? 'w-16' : 'w-64'
        }`}
      >
        <nav className="flex flex-col h-full p-3">
          <div className="flex-1 space-y-1">
            {navItems.map(({ path, label, icon: Icon }) => (
              <Link
                key={path}
                to={path}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-md transition-colors ${
                  isActive(path)
                    ? 'bg-primary-600 text-white'
                    : 'text-slate-400 hover:text-white hover:bg-slate-700'
                }`}
                title={sidebarCollapsed ? label : undefined}
              >
                <Icon className="h-5 w-5 flex-shrink-0" />
                {!sidebarCollapsed && <span className="text-sm font-medium">{label}</span>}
              </Link>
            ))}
          </div>

          {/* User Info at Bottom */}
          {!sidebarCollapsed && (
            <div className="mt-auto pt-3 border-t border-slate-700">
              <div className="px-3 py-2 text-xs text-slate-500">
                <p className="font-medium text-white">{user?.username}</p>
                <p className="capitalize">{user?.role}</p>
              </div>
            </div>
          )}
        </nav>
      </aside>

      {/* Mobile Sidebar */}
      {mobileMenuOpen && (
        <>
          {/* Backdrop */}
          <div
            className="md:hidden fixed inset-0 bg-black/50 z-40"
            onClick={() => setMobileMenuOpen(false)}
          />

          {/* Sidebar Panel */}
          <aside className="md:hidden fixed top-16 left-0 bottom-0 w-64 bg-slate-800 border-r border-slate-700 z-50 shadow-xl">
            <nav className="flex flex-col h-full p-3">
              {/* User Info */}
              <div className="px-3 py-3 mb-3 bg-slate-700/50 rounded-md">
                <p className="text-xs text-slate-500">Logged in as</p>
                <p className="text-sm text-white font-medium">{user?.username}</p>
                <p className="text-xs text-slate-400 capitalize">{user?.role}</p>
              </div>

              {/* Navigation Items */}
              <div className="flex-1 space-y-1">
                {navItems.map(({ path, label, icon: Icon }) => (
                  <Link
                    key={path}
                    to={path}
                    onClick={() => setMobileMenuOpen(false)}
                    className={`flex items-center gap-3 px-3 py-2.5 rounded-md transition-colors ${
                      isActive(path)
                        ? 'bg-primary-600 text-white'
                        : 'text-slate-400 hover:text-white hover:bg-slate-700'
                    }`}
                  >
                    <Icon className="h-5 w-5" />
                    <span className="text-sm font-medium">{label}</span>
                  </Link>
                ))}
              </div>
            </nav>
          </aside>
        </>
      )}
    </>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </QueryClientProvider>
  );
}

function AppContent() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password/:token" element={<ResetPassword />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    );
  }

  return <AuthenticatedApp />;
}

export default App;
