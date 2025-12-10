/**
 * Authentication Context
 * Manages user authentication state and provides auth methods
 */

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

interface User {
  id: number;
  username: string;
  role: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_KEY = 'auth_token';
const USER_KEY = 'auth_user';

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize auth state from localStorage and validate with backend
  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem(TOKEN_KEY);
      const storedUser = localStorage.getItem(USER_KEY);

      if (storedToken && storedUser) {
        try {
          // Validate token with backend
          const response = await fetch('/api/auth/me', {
            headers: {
              'Authorization': `Bearer ${storedToken}`,
            },
          });

          if (response.ok) {
            // Token is valid, restore auth state
            const userData = await response.json();
            setToken(storedToken);
            setUser(userData);
            localStorage.setItem(USER_KEY, JSON.stringify(userData));
          } else {
            // Token is invalid or expired, clear storage
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
          }
        } catch (e) {
          // Validation failed, clear storage
          localStorage.removeItem(TOKEN_KEY);
          localStorage.removeItem(USER_KEY);
        }
      }

      setIsLoading(false);
    };

    initAuth();
  }, []);

  const login = async (username: string, password: string) => {
    const maxRetries = 3;
    const retryDelay = 1000; // Start with 1 second

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ username, password }),
        });

        // Check if response is HTML (backend down)
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('text/html')) {
          throw new Error('BACKEND_UNAVAILABLE');
        }

        // Try to parse response as JSON
        let data;
        try {
          if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Login failed');
          }
          data = await response.json();
        } catch (parseError) {
          // If JSON parsing fails, backend is likely returning HTML error page
          if (parseError instanceof SyntaxError) {
            throw new Error('BACKEND_UNAVAILABLE');
          }
          throw parseError;
        }

        if (!data.success || !data.token) {
          throw new Error(data.message || 'Login failed');
        }

        // Store token and user info
        const userData: User = {
          id: 0, // Backend doesn't return ID yet, will get from /me endpoint
          username: data.username,
          role: data.role,
        };

        localStorage.setItem(TOKEN_KEY, data.token);
        localStorage.setItem(USER_KEY, JSON.stringify(userData));

        setToken(data.token);
        setUser(userData);

        // Fetch full user info
        await checkAuth();

        return; // Success, exit retry loop
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';

        // If backend is unavailable and we have retries left, wait and retry
        if (errorMessage === 'BACKEND_UNAVAILABLE' && attempt < maxRetries) {
          const delay = retryDelay * Math.pow(2, attempt); // Exponential backoff
          console.log(`Backend unavailable, retrying in ${delay}ms... (attempt ${attempt + 1}/${maxRetries})`);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }

        // If it's the last attempt or not a backend unavailable error, throw
        if (errorMessage === 'BACKEND_UNAVAILABLE') {
          throw new Error('Backend is starting up. Please wait a moment and try again.');
        }

        throw error;
      }
    }
  };

  const logout = async () => {
    if (token) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
      } catch (error) {
        // Log the error but continue with logout
        console.error('Logout request failed:', error);
      }
    }

    // Clear local state
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setToken(null);
    setUser(null);
  };

  const checkAuth = async () => {
    const currentToken = token || localStorage.getItem(TOKEN_KEY);

    if (!currentToken) {
      setUser(null);
      setToken(null);
      return;
    }

    try {
      const response = await fetch('/api/auth/me', {
        headers: {
          'Authorization': `Bearer ${currentToken}`,
        },
      });

      if (!response.ok) {
        // Token is invalid or expired
        throw new Error('Authentication failed');
      }

      const userData = await response.json();

      setUser(userData);
      setToken(currentToken);
      localStorage.setItem(USER_KEY, JSON.stringify(userData));
    } catch (error) {
      // Clear invalid auth state
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      setToken(null);
      setUser(null);
    }
  };

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated: !!user && !!token,
    isLoading,
    login,
    logout,
    checkAuth,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
