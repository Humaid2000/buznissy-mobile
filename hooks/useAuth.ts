import { useState, useEffect } from 'react';
import * as SecureStore from 'expo-secure-store';

interface User {
  id: string;
  fullNameEn: string;
  fullNameAr?: string;
  email: string;
  phone?: string;
  businessType: 'influencer' | 'service-provider' | 'product-provider';
  businessName?: string;
  location?: string;
  subscriptionPlan?: string;
  businessStatus?: string;
  // Admin role system fields
  role: 'user' | 'admin' | 'super_admin';
  permissions: string[];
  isActive: boolean;
  lastLoginAt?: string;
  business?: any;
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  // Admin role checking functions
  isAdmin: boolean;
  isSuperAdmin: boolean;
  token: string | null;
}

const API_BASE_URL = process.env.EXPO_PUBLIC_API_URL || 'https://55fa5918-9584-4341-a1d5-dc26a51aac72-00-3q2cncwrn7nls.sisko.replit.dev';
const TOKEN_KEY = 'auth_token';
const USER_KEY = 'auth_user';

export function useAuth() {
  const [authState, setAuthState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    isAdmin: false,
    isSuperAdmin: false,
    token: null,
  });

  // Helper function to determine admin status
  const getAdminStatus = (user: User | null) => {
    if (!user || !user.isActive) return { isAdmin: false, isSuperAdmin: false };
    return {
      isAdmin: user.role === 'admin' || user.role === 'super_admin',
      isSuperAdmin: user.role === 'super_admin'
    };
  };

  // Helper function to make authenticated API requests
  const makeAuthenticatedRequest = async (url: string, options: RequestInit = {}) => {
    const token = await SecureStore.getItemAsync(TOKEN_KEY);
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...options.headers as Record<string, string>,
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    return fetch(url, {
      ...options,
      headers,
    });
  };

  useEffect(() => {
    loadAuthState();
  }, []);

  const loadAuthState = async () => {
    try {
      setAuthState(prev => ({ ...prev, isLoading: true }));

      // Get stored token and user data
      const [storedToken, storedUserData] = await Promise.all([
        SecureStore.getItemAsync(TOKEN_KEY),
        SecureStore.getItemAsync(USER_KEY)
      ]);

      let user: User | null = null;
      let token: string | null = storedToken;

      // Parse stored user if available
      if (storedUserData) {
        try {
          user = JSON.parse(storedUserData);
        } catch (e) {
          console.error('Error parsing stored user data:', e);
          await SecureStore.deleteItemAsync(USER_KEY);
        }
      }

      // If we have a token, try to fetch fresh user data from backend
      if (token) {
        try {
          const response = await makeAuthenticatedRequest(`${API_BASE_URL}/api/mobile/user`);
          
          if (response.ok) {
            const backendUser = await response.json();
            if (backendUser) {
              // Map backend user data to mobile user format
              user = {
                id: backendUser.id,
                fullNameEn: backendUser.fullNameEn || backendUser.firstName + ' ' + backendUser.lastName,
                fullNameAr: backendUser.fullNameAr,
                email: backendUser.email,
                phone: backendUser.phone,
                businessType: backendUser.businessType || 'product-provider',
                businessName: backendUser.businessName || backendUser.business?.nameEn,
                location: backendUser.location || backendUser.governorate || 'Oman',
                subscriptionPlan: backendUser.subscriptionPlan || 'Professional AI',
                businessStatus: backendUser.businessStatus || (backendUser.isActive ? 'Active' : 'Inactive'),
                role: backendUser.role || 'user',
                permissions: backendUser.permissions || [],
                isActive: backendUser.isActive ?? true,
                lastLoginAt: backendUser.lastLoginAt,
                business: backendUser.business
              };
              
              // Update stored user data
              await SecureStore.setItemAsync(USER_KEY, JSON.stringify(user));
            }
          } else if (response.status === 401) {
            // Token expired or invalid, clear stored data
            await Promise.all([
              SecureStore.deleteItemAsync(TOKEN_KEY),
              SecureStore.deleteItemAsync(USER_KEY)
            ]);
            token = null;
            user = null;
          }
        } catch (fetchError) {
          console.log('Backend not available, using cached data:', fetchError);
          // Keep using cached user data if backend is not available
        }
      }

      if (user && token) {
        const adminStatus = getAdminStatus(user);
        setAuthState({
          user,
          isAuthenticated: true,
          isLoading: false,
          token,
          ...adminStatus
        });
      } else {
        setAuthState({
          user: null,
          isAuthenticated: false,
          isLoading: false,
          isAdmin: false,
          isSuperAdmin: false,
          token: null,
        });
      }
    } catch (error) {
      console.error('Error loading auth state:', error);
      setAuthState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        isAdmin: false,
        isSuperAdmin: false,
        token: null,
      });
    }
  };

  const login = async (email: string, password?: string) => {
    try {
      setAuthState(prev => ({ ...prev, isLoading: true }));
      
      const response = await fetch(`${API_BASE_URL}/api/mobile/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Login failed');
      }

      const data = await response.json();
      
      if (data.success && data.token && data.user) {
        // Store token and user data
        await Promise.all([
          SecureStore.setItemAsync(TOKEN_KEY, data.token),
          SecureStore.setItemAsync(USER_KEY, JSON.stringify(data.user))
        ]);
        
        const adminStatus = getAdminStatus(data.user);
        setAuthState({
          user: data.user,
          isAuthenticated: true,
          isLoading: false,
          token: data.token,
          ...adminStatus
        });
        
        return { success: true };
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      console.error('Login error:', error);
      setAuthState(prev => ({ ...prev, isLoading: false }));
      return { success: false, error: (error as Error).message };
    }
  };

  const loginDemo = async () => {
    try {
      setAuthState(prev => ({ ...prev, isLoading: true }));
      
      const response = await fetch(`${API_BASE_URL}/api/mobile/demo-login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Demo login failed');
      }

      const data = await response.json();
      
      if (data.success && data.token && data.user) {
        // Store token and user data
        await Promise.all([
          SecureStore.setItemAsync(TOKEN_KEY, data.token),
          SecureStore.setItemAsync(USER_KEY, JSON.stringify(data.user))
        ]);
        
        const adminStatus = getAdminStatus(data.user);
        setAuthState({
          user: data.user,
          isAuthenticated: true,
          isLoading: false,
          token: data.token,
          ...adminStatus
        });
        
        return { success: true };
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      console.error('Demo login error:', error);
      setAuthState(prev => ({ ...prev, isLoading: false }));
      return { success: false, error: (error as Error).message };
    }
  };

  const logout = async () => {
    try {
      // Try to call logout endpoint if we have a token
      if (authState.token) {
        try {
          await makeAuthenticatedRequest(`${API_BASE_URL}/api/mobile/logout`, {
            method: 'POST',
          });
        } catch (e) {
          console.log('Logout endpoint call failed, proceeding with local logout');
        }
      }
      
      // Clear stored data
      await Promise.all([
        SecureStore.deleteItemAsync(TOKEN_KEY),
        SecureStore.deleteItemAsync(USER_KEY)
      ]);
      
      setAuthState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        isAdmin: false,
        isSuperAdmin: false,
        token: null,
      });
      
      return { success: true };
    } catch (error) {
      console.error('Error during logout:', error);
      return { success: false, error: (error as Error).message };
    }
  };

  const updateUser = async (updatedUser: Partial<User>) => {
    if (authState.user) {
      const newUser = { ...authState.user, ...updatedUser };
      const adminStatus = getAdminStatus(newUser);
      try {
        await SecureStore.setItemAsync(USER_KEY, JSON.stringify(newUser));
        setAuthState(prev => ({
          ...prev,
          user: newUser,
          ...adminStatus
        }));
      } catch (error) {
        console.error('Error updating user:', error);
      }
    }
  };

  return {
    ...authState,
    login,
    loginDemo,
    logout,
    updateUser,
    refreshAuth: loadAuthState,
    makeAuthenticatedRequest,
    // Admin helper functions
    checkAdminAccess: () => authState.isAdmin && authState.user?.isActive,
    checkSuperAdminAccess: () => authState.isSuperAdmin && authState.user?.isActive,
    hasPermission: (permission: string) => 
      authState.user?.permissions?.includes(permission) || authState.isSuperAdmin,
  };
}
