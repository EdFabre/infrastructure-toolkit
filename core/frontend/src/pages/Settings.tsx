/**
 * Settings Page Component
 * User settings including password management
 */

import React, { useState, FormEvent } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Key, CheckCircle, XCircle, AlertCircle } from 'lucide-react';

interface PasswordChangeForm {
  oldPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export const Settings: React.FC = () => {
  const { user, token } = useAuth();
  const [formData, setFormData] = useState<PasswordChangeForm>({
    oldPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    // Clear messages when user starts typing
    setError('');
    setSuccess('');
  };

  const validateForm = (): string | null => {
    if (!formData.oldPassword) {
      return 'Current password is required';
    }
    if (!formData.newPassword) {
      return 'New password is required';
    }
    if (formData.newPassword.length < 8) {
      return 'New password must be at least 8 characters';
    }
    if (formData.newPassword === formData.oldPassword) {
      return 'New password must be different from current password';
    }
    if (formData.newPassword !== formData.confirmPassword) {
      return 'New passwords do not match';
    }
    return null;
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Validate form
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          old_password: formData.oldPassword,
          new_password: formData.newPassword
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to change password');
      }

      setSuccess('Password changed successfully!');
      // Clear form
      setFormData({
        oldPassword: '',
        newPassword: '',
        confirmPassword: ''
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-3 bg-blue-500/10 rounded-lg">
          <Key className="h-8 w-8 text-blue-400" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-white">Settings</h1>
          <p className="text-slate-400 mt-1">Manage your account settings</p>
        </div>
      </div>

      {/* User Information Card */}
      <div className="card">
        <h2 className="text-xl font-semibold text-white mb-4">Account Information</h2>
        <div className="space-y-3">
          <div className="flex items-center justify-between py-2">
            <span className="text-slate-400">Username</span>
            <span className="text-white font-medium">{user?.username}</span>
          </div>
          <div className="flex items-center justify-between py-2">
            <span className="text-slate-400">Role</span>
            <span className="text-white font-medium capitalize">{user?.role}</span>
          </div>
          <div className="flex items-center justify-between py-2">
            <span className="text-slate-400">Status</span>
            <span className="flex items-center gap-2 text-green-400 font-medium">
              <CheckCircle className="h-4 w-4" />
              Active
            </span>
          </div>
        </div>
      </div>

      {/* Change Password Card */}
      <div className="card">
        <h2 className="text-xl font-semibold text-white mb-4">Change Password</h2>

        {/* Default Password Warning */}
        {user?.username === 'admin' && (
          <div className="mb-6 p-4 bg-yellow-500/10 border border-yellow-500/50 rounded-lg">
            <div className="flex items-start gap-3">
              <AlertCircle className="h-5 w-5 text-yellow-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-yellow-400 font-medium">Default Credentials Detected</p>
                <p className="text-slate-400 text-sm mt-1">
                  You are using the default admin account. Please change your password for security.
                </p>
              </div>
            </div>
          </div>
        )}

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

        {/* Password Change Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Current Password */}
          <div>
            <label htmlFor="oldPassword" className="block text-sm font-medium text-slate-300 mb-2">
              Current Password
            </label>
            <input
              type="password"
              id="oldPassword"
              name="oldPassword"
              value={formData.oldPassword}
              onChange={handleInputChange}
              className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="Enter your current password"
              disabled={isLoading}
            />
          </div>

          {/* New Password */}
          <div>
            <label htmlFor="newPassword" className="block text-sm font-medium text-slate-300 mb-2">
              New Password
            </label>
            <input
              type="password"
              id="newPassword"
              name="newPassword"
              value={formData.newPassword}
              onChange={handleInputChange}
              className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="Enter your new password"
              disabled={isLoading}
            />
            <p className="mt-1 text-xs text-slate-500">Must be at least 8 characters</p>
          </div>

          {/* Confirm New Password */}
          <div>
            <label htmlFor="confirmPassword" className="block text-sm font-medium text-slate-300 mb-2">
              Confirm New Password
            </label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleInputChange}
              className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="Confirm your new password"
              disabled={isLoading}
            />
          </div>

          {/* Submit Button */}
          <div className="pt-4">
            <button
              type="submit"
              disabled={isLoading}
              className="w-full px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors duration-200 flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <div className="h-5 w-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Changing Password...</span>
                </>
              ) : (
                <>
                  <Key className="h-5 w-5" />
                  <span>Change Password</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
