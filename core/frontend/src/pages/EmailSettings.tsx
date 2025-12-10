/**
 * Email Settings Page Component (Admin Only)
 * Configure SMTP settings for email notifications
 */

import React, { useState, useEffect, FormEvent } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Mail, Send, CheckCircle, XCircle, AlertCircle, Server } from 'lucide-react';

interface EmailConfigForm {
  smtp_host: string;
  smtp_port: number;
  smtp_user: string;
  smtp_password: string;
  from_email: string;
  from_name: string;
  use_tls: boolean;
  use_ssl: boolean;
}

interface TestEmailForm {
  to_email: string;
  to_name: string;
}

export const EmailSettings: React.FC = () => {
  const { user, token } = useAuth();
  const [isConfigured, setIsConfigured] = useState(false);
  const [isCheckingStatus, setIsCheckingStatus] = useState(true);

  const [configForm, setConfigForm] = useState<EmailConfigForm>({
    smtp_host: '',
    smtp_port: 587,
    smtp_user: '',
    smtp_password: '',
    from_email: '',
    from_name: 'Infrastructure Toolkit',
    use_tls: true,
    use_ssl: false
  });

  const [testForm, setTestForm] = useState<TestEmailForm>({
    to_email: user?.username || '',
    to_name: user?.username || ''
  });

  const [isLoading, setIsLoading] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [testSuccess, setTestSuccess] = useState('');
  const [testError, setTestError] = useState('');

  // Check email status on mount
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const response = await fetch('/api/auth/email/status', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (response.ok) {
          const data = await response.json();
          setIsConfigured(data.is_configured);
        }
      } catch (err) {
        console.error('Failed to check email status:', err);
      } finally {
        setIsCheckingStatus(false);
      }
    };

    checkStatus();
  }, [token]);

  const handleConfigInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setConfigForm(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : (name === 'smtp_port' ? parseInt(value) || 587 : value)
    }));
    setError('');
    setSuccess('');
  };

  const handleTestInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setTestForm(prev => ({
      ...prev,
      [name]: value
    }));
    setTestError('');
    setTestSuccess('');
  };

  const validateConfigForm = (): string | null => {
    if (!configForm.smtp_host) return 'SMTP host is required';
    if (!configForm.smtp_port || configForm.smtp_port < 1 || configForm.smtp_port > 65535) {
      return 'Valid SMTP port is required (1-65535)';
    }
    if (!configForm.smtp_user) return 'SMTP username is required';
    if (!configForm.smtp_password) return 'SMTP password is required';
    if (!configForm.from_email) return 'From email is required';
    if (!configForm.from_email.includes('@')) return 'Valid email address required';
    return null;
  };

  const handleConfigSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    const validationError = validateConfigForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch('/api/auth/email/config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(configForm)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to configure email');
      }

      setSuccess('Email configuration saved successfully');
      setIsConfigured(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to configure email');
    } finally {
      setIsLoading(false);
    }
  };

  const handleTestEmail = async (e: FormEvent) => {
    e.preventDefault();
    setTestError('');
    setTestSuccess('');

    if (!testForm.to_email) {
      setTestError('Email address is required');
      return;
    }

    setIsTesting(true);

    try {
      const response = await fetch('/api/auth/email/test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(testForm)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to send test email');
      }

      setTestSuccess(data.message);
    } catch (err) {
      setTestError(err instanceof Error ? err.message : 'Failed to send test email');
    } finally {
      setIsTesting(false);
    }
  };

  if (isCheckingStatus) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading email settings...</p>
        </div>
      </div>
    );
  }

  // Check if user is admin
  if (user?.role !== 'admin') {
    return (
      <div className="space-y-6">
        <div className="card">
          <div className="flex items-center gap-3 text-red-400">
            <XCircle className="h-8 w-8" />
            <div>
              <h2 className="text-xl font-semibold">Access Denied</h2>
              <p className="text-slate-400 mt-1">Only administrators can configure email settings.</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-3 bg-purple-500/10 rounded-lg">
          <Mail className="h-8 w-8 text-purple-400" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-white">Email Settings</h1>
          <p className="text-slate-400 mt-1">Configure SMTP settings for email notifications</p>
        </div>
      </div>

      {/* Status Card */}
      <div className="card">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white mb-1">Email Service Status</h2>
            <p className="text-sm text-slate-400">Current configuration status</p>
          </div>
          <div className={`flex items-center gap-2 px-4 py-2 rounded-lg ${
            isConfigured
              ? 'bg-green-500/10 text-green-400'
              : 'bg-yellow-500/10 text-yellow-400'
          }`}>
            {isConfigured ? (
              <>
                <CheckCircle className="h-5 w-5" />
                <span className="font-medium">Configured</span>
              </>
            ) : (
              <>
                <AlertCircle className="h-5 w-5" />
                <span className="font-medium">Not Configured</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* SMTP Configuration Card */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <Server className="h-6 w-6 text-purple-400" />
          <h2 className="text-xl font-semibold text-white">SMTP Configuration</h2>
        </div>

        {/* Success Message */}
        {success && (
          <div className="mb-6 p-4 bg-green-500/10 border border-green-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-green-400">
              <CheckCircle className="h-5 w-5" />
              <span>{success}</span>
            </div>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="mb-6 p-4 bg-red-500/10 border border-red-500/50 rounded-lg">
            <div className="flex items-center gap-2 text-red-400">
              <XCircle className="h-5 w-5" />
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Info Box */}
        <div className="mb-6 p-4 bg-blue-500/10 border border-blue-500/50 rounded-lg">
          <div className="flex items-start gap-2 text-blue-400 text-sm">
            <AlertCircle className="h-5 w-5 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-medium">ProtonMail Bridge Available</p>
              <p className="mt-1 text-xs text-blue-300">
                You can use the ProtonMail Bridge server at <span className="font-mono">boss-04:1025</span> (192.168.1.14:1025)
              </p>
            </div>
          </div>
        </div>

        {/* Configuration Form */}
        <form onSubmit={handleConfigSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* SMTP Host */}
            <div>
              <label htmlFor="smtp_host" className="block text-sm font-medium text-slate-300 mb-2">
                SMTP Host
              </label>
              <input
                type="text"
                id="smtp_host"
                name="smtp_host"
                value={configForm.smtp_host}
                onChange={handleConfigInputChange}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
                placeholder="e.g., 192.168.1.14 or smtp.example.com"
                disabled={isLoading}
              />
            </div>

            {/* SMTP Port */}
            <div>
              <label htmlFor="smtp_port" className="block text-sm font-medium text-slate-300 mb-2">
                SMTP Port
              </label>
              <input
                type="number"
                id="smtp_port"
                name="smtp_port"
                value={configForm.smtp_port}
                onChange={handleConfigInputChange}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
                placeholder="587"
                min="1"
                max="65535"
                disabled={isLoading}
              />
              <p className="mt-1 text-xs text-slate-500">Common: 587 (TLS), 465 (SSL), 25 (Plain)</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* SMTP Username */}
            <div>
              <label htmlFor="smtp_user" className="block text-sm font-medium text-slate-300 mb-2">
                SMTP Username
              </label>
              <input
                type="text"
                id="smtp_user"
                name="smtp_user"
                value={configForm.smtp_user}
                onChange={handleConfigInputChange}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
                placeholder="username or email"
                disabled={isLoading}
              />
            </div>

            {/* SMTP Password */}
            <div>
              <label htmlFor="smtp_password" className="block text-sm font-medium text-slate-300 mb-2">
                SMTP Password
              </label>
              <input
                type="password"
                id="smtp_password"
                name="smtp_password"
                value={configForm.smtp_password}
                onChange={handleConfigInputChange}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
                placeholder="••••••••"
                disabled={isLoading}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* From Email */}
            <div>
              <label htmlFor="from_email" className="block text-sm font-medium text-slate-300 mb-2">
                From Email Address
              </label>
              <input
                type="email"
                id="from_email"
                name="from_email"
                value={configForm.from_email}
                onChange={handleConfigInputChange}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
                placeholder="noreply@example.com"
                disabled={isLoading}
              />
            </div>

            {/* From Name */}
            <div>
              <label htmlFor="from_name" className="block text-sm font-medium text-slate-300 mb-2">
                From Name
              </label>
              <input
                type="text"
                id="from_name"
                name="from_name"
                value={configForm.from_name}
                onChange={handleConfigInputChange}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
                placeholder="Infrastructure Toolkit"
                disabled={isLoading}
              />
            </div>
          </div>

          {/* Encryption Options */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center">
              <input
                type="checkbox"
                id="use_tls"
                name="use_tls"
                checked={configForm.use_tls}
                onChange={handleConfigInputChange}
                className="w-4 h-4 text-purple-600 bg-slate-800 border-slate-700 rounded focus:ring-purple-500"
                disabled={isLoading}
              />
              <label htmlFor="use_tls" className="ml-2 text-sm font-medium text-slate-300">
                Use TLS (STARTTLS)
              </label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                id="use_ssl"
                name="use_ssl"
                checked={configForm.use_ssl}
                onChange={handleConfigInputChange}
                className="w-4 h-4 text-purple-600 bg-slate-800 border-slate-700 rounded focus:ring-purple-500"
                disabled={isLoading}
              />
              <label htmlFor="use_ssl" className="ml-2 text-sm font-medium text-slate-300">
                Use SSL/TLS (implicit)
              </label>
            </div>
          </div>

          {/* Submit Button */}
          <div className="pt-4">
            <button
              type="submit"
              disabled={isLoading}
              className="w-full px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors duration-200 flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <div className="h-5 w-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Saving Configuration...</span>
                </>
              ) : (
                <>
                  <Server className="h-5 w-5" />
                  <span>Save Configuration</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Test Email Card */}
      {isConfigured && (
        <div className="card">
          <div className="flex items-center gap-3 mb-6">
            <Send className="h-6 w-6 text-green-400" />
            <h2 className="text-xl font-semibold text-white">Test Email</h2>
          </div>

          {/* Test Success Message */}
          {testSuccess && (
            <div className="mb-6 p-4 bg-green-500/10 border border-green-500/50 rounded-lg">
              <div className="flex items-center gap-2 text-green-400">
                <CheckCircle className="h-5 w-5" />
                <span>{testSuccess}</span>
              </div>
            </div>
          )}

          {/* Test Error Message */}
          {testError && (
            <div className="mb-6 p-4 bg-red-500/10 border border-red-500/50 rounded-lg">
              <div className="flex items-center gap-2 text-red-400">
                <XCircle className="h-5 w-5" />
                <span>{testError}</span>
              </div>
            </div>
          )}

          {/* Test Form */}
          <form onSubmit={handleTestEmail} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="to_email" className="block text-sm font-medium text-slate-300 mb-2">
                  Recipient Email
                </label>
                <input
                  type="email"
                  id="to_email"
                  name="to_email"
                  value={testForm.to_email}
                  onChange={handleTestInputChange}
                  className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-green-500 focus:ring-1 focus:ring-green-500"
                  placeholder="test@example.com"
                  disabled={isTesting}
                />
              </div>

              <div>
                <label htmlFor="to_name" className="block text-sm font-medium text-slate-300 mb-2">
                  Recipient Name (Optional)
                </label>
                <input
                  type="text"
                  id="to_name"
                  name="to_name"
                  value={testForm.to_name}
                  onChange={handleTestInputChange}
                  className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-green-500 focus:ring-1 focus:ring-green-500"
                  placeholder="Test User"
                  disabled={isTesting}
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isTesting}
              className="w-full px-6 py-3 bg-green-600 hover:bg-green-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors duration-200 flex items-center justify-center gap-2"
            >
              {isTesting ? (
                <>
                  <div className="h-5 w-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Sending Test Email...</span>
                </>
              ) : (
                <>
                  <Send className="h-5 w-5" />
                  <span>Send Test Email</span>
                </>
              )}
            </button>
          </form>
        </div>
      )}
    </div>
  );
};
