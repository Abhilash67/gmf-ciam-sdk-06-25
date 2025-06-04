# GMF CIAM SDK Documentation

[![Version](https://img.shields.io/npm/v/gmf-ciam-sdk.svg)](https://www.npmjs.com/package/gmf-ciam-sdk)
[![License](https://img.shields.io/npm/l/gmf-ciam-sdk.svg)](https://github.com/your-org/gmf-ciam-sdk/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

A comprehensive Customer Identity and Access Management (CIAM) SDK for JavaScript/TypeScript applications with Auth0 integration and custom endpoint support.

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Features](#features)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Custom Endpoints](#custom-endpoints)
- [Error Handling](#error-handling)
- [Examples](#examples)
- [TypeScript Support](#typescript-support)
- [Migration Guide](#migration-guide)
- [Troubleshooting](#troubleshooting)

## 🚀 Installation

```bash
npm install gmf-ciam-sdk
```

```bash
yarn add gmf-ciam-sdk
```

## ⚡ Quick Start

### Basic Setup

```typescript
import GMFCIAMAuth, { AuthProvider, UserProfile } from 'gmf-ciam-sdk';

// Configure Auth0
const config = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'your-api-audience',
  redirectUri: window.location.origin,
  scope: 'openid profile email offline_access',
  cacheLocation: 'sessionstorage'
};

// Initialize the auth provider
const authProvider = await GMFCIAMAuth.createAuthProvider('auth0', config);

// Login
await authProvider.login();

// Check authentication status
const isAuthenticated = await authProvider.isAuthenticated();

// Get user profile
if (isAuthenticated) {
  const userProfile = await authProvider.getUserProfile();
  console.log('User:', userProfile);
}
```

### With Custom Endpoints

```typescript
const configWithCustomEndpoints = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'your-api-audience',
  redirectUri: window.location.origin,
  scope: 'openid profile email offline_access',
  cacheLocation: 'sessionstorage',
  
  // Custom endpoints for your API
  customEndpoints: {
    passwordReset: 'https://your-api.com/auth/password-reset',
    passwordChange: 'https://your-api.com/auth/password-change',
    userProfileUpdate: 'https://your-api.com/auth/profile-update'
  }
};

const authProvider = await GMFCIAMAuth.createAuthProvider('auth0', configWithCustomEndpoints);
```

## ✨ Features

- **🔐 Auth0 Integration** - Complete Auth0 authentication flow
- **🔄 Token Management** - Automatic token refresh and validation
- **🛡️ Session Storage** - Secure session-only storage (no persistent localStorage)
- **🔧 Custom Endpoints** - Support for your own API endpoints
- **📝 Profile Management** - Update user profiles with first/last name support
- **🔑 Password Management** - Reset and change passwords
- **⚠️ Error Handling** - Comprehensive error handling with detailed error codes
- **📱 TypeScript Ready** - Full TypeScript support with type definitions
- **🧪 Testing Support** - Built-in testing utilities and mock capabilities

## ⚙️ Configuration

### Auth0 Configuration

```typescript
interface AuthConfig {
  domain: string;                    // Auth0 domain (required)
  clientId: string;                  // Auth0 client ID (required)
  audience?: string;                 // Auth0 API audience
  redirectUri?: string;              // Redirect URI (defaults to current origin)
  scope?: string;                    // OAuth scopes (default: 'openid profile email offline_access')
  responseType?: string;             // OAuth response type (default: 'code')
  cacheLocation?: 'sessionstorage';  // Storage location (sessionstorage only)
  clientSecret?: string;             // Client secret (for server-side operations)
  managementApiAudience?: string;    // Management API audience
  customEndpoints?: {                // Optional custom endpoints
    passwordReset?: string;
    passwordChange?: string;
    userProfileUpdate?: string;
  };
}
```

### Default Configuration

```typescript
const defaultConfig = {
  redirectUri: window.location.origin,
  scope: 'openid profile email offline_access',
  responseType: 'code',
  cacheLocation: 'sessionstorage',
  managementApiAudience: `https://${domain}/api/v2/`
};
```

## 📚 API Reference

### Core Methods

#### `createAuthProvider(type, config)`

Creates and initializes an authentication provider.

```typescript
const authProvider = await GMFCIAMAuth.createAuthProvider('auth0', config);
```

**Parameters:**
- `type`: `'auth0'` - Provider type
- `config`: `AuthConfig` - Configuration object

**Returns:** `Promise<AuthProvider>`

#### `login()`

Initiates the authentication flow. Redirects to Auth0 login page.

```typescript
await authProvider.login();
```

**Returns:** `Promise<void>`

#### `logout()`

Logs out the user and redirects to Auth0 logout page.

```typescript
authProvider.logout();
```

**Returns:** `void`

#### `isAuthenticated()`

Checks if the user is currently authenticated.

```typescript
const isAuth = await authProvider.isAuthenticated();
```

**Returns:** `Promise<boolean>`

#### `getAccessToken()`

Retrieves the current access token.

```typescript
const token = await authProvider.getAccessToken();
```

**Returns:** `Promise<string>`

#### `refreshToken()`

Refreshes the access token using the refresh token.

```typescript
const success = await authProvider.refreshToken();
```

**Returns:** `Promise<boolean>`

### Profile Management

#### `getUserProfile(forceRefresh?)`

Retrieves the user's profile information.

```typescript
const profile = await authProvider.getUserProfile();
const freshProfile = await authProvider.getUserProfile(true);
```

**Parameters:**
- `forceRefresh`: `boolean` (optional) - Force refresh from server

**Returns:** `Promise<UserProfile>`

#### `getDetailedUserProfile()`

Retrieves detailed user profile from Auth0 Management API.

```typescript
const detailedProfile = await authProvider.getDetailedUserProfile();
```

**Returns:** `Promise<UserProfile>`

#### `updateUserProfile(updates)`

Updates the user's profile information.

```typescript
const updates = {
  name: 'John Doe',
  nickname: 'johnny',
  given_name: 'John',     // Maps to firstname in custom endpoints
  family_name: 'Doe',     // Maps to lastname in custom endpoints
  user_metadata: {
    preferences: {
      theme: 'dark',
      language: 'en'
    }
  }
};

const updatedProfile = await authProvider.updateUserProfile(updates);
```

**Parameters:**
- `updates`: `ProfileUpdates` - Profile fields to update

**Returns:** `Promise<UserProfile>`

### Password Management

#### `resetPassword(email)`

Initiates password reset for the given email.

```typescript
const result = await authProvider.resetPassword('user@example.com');
console.log(result); // "Password reset email sent successfully"
```

**Parameters:**
- `email`: `string` - User's email address

**Returns:** `Promise<string>`

#### `changePassword(oldPassword, newPassword)`

Changes the user's password.

```typescript
const result = await authProvider.changePassword('currentPass123', 'newPass456');
console.log(result); // "Password changed successfully"
```

**Parameters:**
- `oldPassword`: `string` - Current password
- `newPassword`: `string` - New password (minimum 8 characters)

**Returns:** `Promise<string>`

### Error Handling

#### `onError(callback)`

Registers an error callback to handle authentication errors.

```typescript
authProvider.onError((error) => {
  console.error('Auth Error:', error.name, error.code, error.message);
  
  switch (error.name) {
    case 'AuthenticationError':
      // Handle authentication errors
      break;
    case 'NetworkError':
      // Handle network errors
      break;
    case 'TokenError':
      // Handle token errors
      break;
  }
});
```

**Parameters:**
- `callback`: `(error: AuthError) => void` - Error callback function

#### `getLastError()`

Retrieves the last error that occurred.

```typescript
const lastError = authProvider.getLastError();
if (lastError) {
  console.log('Last error:', lastError.message);
}
```

**Returns:** `AuthError | null`

#### `clearError()`

Clears the last error.

```typescript
authProvider.clearError();
```

### Utility Methods

#### `validateAuthState()`

Validates the current authentication state.

```typescript
const validation = await authProvider.validateAuthState();
if (validation.valid) {
  console.log('Authentication is valid');
} else {
  console.log('Validation failed:', validation.reason);
}
```

**Returns:** `Promise<AuthValidationResult>`

#### `getAuthStatus()`

Gets comprehensive authentication status information.

```typescript
const status = authProvider.getAuthStatus();
console.log('Auth Status:', status);
```

**Returns:** `AuthStatus`

## 🔌 Custom Endpoints

The SDK supports custom API endpoints that use a specific payload format. When configured, these endpoints will be used instead of the default Auth0 APIs.

### Payload Format

All custom endpoints expect this payload structure:

```typescript
interface CustomEndpointPayload {
  email: string;
  password: string | null;
  firstname: string | null;
  lastname: string | null;
  usermetadata: Record<string, any> | null;
}
```

### Password Reset Endpoint

**Expected Request:**
```http
POST /auth/password-reset
Content-Type: application/json
Authorization: Bearer <optional-token>

{
  "email": "user@example.com",
  "password": null,
  "firstname": null,
  "lastname": null,
  "usermetadata": null
}
```

**Expected Response:**
```json
{
  "message": "Password reset email sent successfully"
}
```

### Password Change Endpoint

**Expected Request:**
```http
POST /auth/password-change
Content-Type: application/json
Authorization: Bearer <access-token>

{
  "email": "user@example.com",
  "password": "newPassword123",
  "firstname": "John",
  "lastname": "Doe",
  "usermetadata": {
    "preferences": {
      "theme": "dark"
    }
  }
}
```

**Expected Response:**
```json
{
  "message": "Password changed successfully"
}
```

### Profile Update Endpoint

**Expected Request:**
```http
POST /auth/profile-update
Content-Type: application/json
Authorization: Bearer <access-token>

{
  "email": "user@example.com",
  "password": null,
  "firstname": "John",
  "lastname": "Doe",
  "usermetadata": {
    "preferences": {
      "theme": "dark",
      "language": "en"
    }
  }
}
```

**Expected Response:**
```json
{
  "sub": "auth0|user-id",
  "email": "user@example.com",
  "given_name": "John",
  "family_name": "Doe",
  "user_metadata": {
    "preferences": {
      "theme": "dark",
      "language": "en"
    }
  }
}
```

### Fallback Behavior

If custom endpoints are not configured, the SDK automatically falls back to standard Auth0 APIs:
- Password reset → Auth0 Database Connection reset
- Password change → Auth0 Management API
- Profile update → Auth0 Management API

## ⚠️ Error Handling

### Error Types

The SDK provides comprehensive error handling with specific error types and codes:

```typescript
type ErrorType = 
  | 'AuthenticationError'    // Login/authentication failures
  | 'ConfigurationError'     // SDK configuration issues
  | 'NetworkError'          // HTTP/network issues
  | 'TokenError'            // Token-related problems
  | 'ValidationError'       // Input validation failures
  | 'OperationError';       // General operation errors
```

### Common Error Codes

#### Authentication Errors
- `NOT_AUTHENTICATED` - User not logged in
- `INCORRECT_PASSWORD` - Wrong password provided
- `USER_NOT_FOUND` - Email not found in system
- `INVALID_STATE` - CSRF protection failure

#### Token Errors
- `TOKEN_EXPIRED` - Access token has expired
- `INVALID_REFRESH_TOKEN` - Refresh token is invalid
- `NO_REFRESH_TOKEN` - No refresh token available
- `INVALID_ACCESS_TOKEN` - Access token is invalid

#### Network Errors
- `NETWORK_ERROR` - General network failure
- `TOKEN_EXCHANGE_ERROR` - Token exchange failed
- `PASSWORD_RESET_ERROR` - Password reset request failed

#### Validation Errors
- `MISSING_EMAIL` - Email address required
- `INVALID_EMAIL_FORMAT` - Invalid email format
- `PASSWORD_TOO_SHORT` - Password under 8 characters
- `EMPTY_UPDATES` - No profile updates provided

### Error Handling Example

```typescript
// Global error handling
authProvider.onError((error) => {
  switch (error.code) {
    case 'TOKEN_EXPIRED':
      // Automatically refresh token
      authProvider.refreshToken().catch(() => {
        // Redirect to login if refresh fails
        authProvider.login();
      });
      break;
      
    case 'NETWORK_ERROR':
      showNotification('Network error. Please check your connection.', 'error');
      break;
      
    case 'INVALID_EMAIL_FORMAT':
      showNotification('Please enter a valid email address.', 'warning');
      break;
      
    default:
      showNotification(error.message, 'error');
  }
});

// Method-specific error handling
try {
  await authProvider.changePassword('old', 'new');
} catch (error) {
  if (error.code === 'INCORRECT_PASSWORD') {
    showNotification('Current password is incorrect.', 'error');
  } else {
    showNotification('Password change failed.', 'error');
  }
}
```

## 💡 Examples

### React Hook Example

```typescript
import { useEffect, useState } from 'react';
import GMFCIAMAuth, { AuthProvider, UserProfile } from 'gmf-ciam-sdk';

export function useAuth() {
  const [authProvider, setAuthProvider] = useState<AuthProvider | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initAuth = async () => {
      try {
        const provider = await GMFCIAMAuth.createAuthProvider('auth0', {
          domain: 'your-domain.auth0.com',
          clientId: 'your-client-id',
          audience: 'your-api-audience',
          cacheLocation: 'sessionstorage'
        });

        // Set up error handling
        provider.onError((error) => {
          console.error('Auth Error:', error);
        });

        setAuthProvider(provider);

        // Check authentication status
        const authenticated = await provider.isAuthenticated();
        setIsAuthenticated(authenticated);

        if (authenticated) {
          const profile = await provider.getUserProfile();
          setUserProfile(profile);
        }
      } catch (error) {
        console.error('Auth initialization failed:', error);
      } finally {
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  const login = async () => {
    if (authProvider) {
      await authProvider.login();
    }
  };

  const logout = () => {
    if (authProvider) {
      authProvider.logout();
    }
  };

  const updateProfile = async (updates: any) => {
    if (authProvider) {
      const updated = await authProvider.updateUserProfile(updates);
      setUserProfile(updated);
      return updated;
    }
  };

  return {
    authProvider,
    isAuthenticated,
    userProfile,
    loading,
    login,
    logout,
    updateProfile
  };
}
```

### Angular Service Example

```typescript
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import GMFCIAMAuth, { AuthProvider, UserProfile } from 'gmf-ciam-sdk';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private authProvider: AuthProvider | null = null;
  private authStateSubject = new BehaviorSubject<boolean>(false);
  private userProfileSubject = new BehaviorSubject<UserProfile | null>(null);

  public authState$ = this.authStateSubject.asObservable();
  public userProfile$ = this.userProfileSubject.asObservable();

  async initialize() {
    try {
      this.authProvider = await GMFCIAMAuth.createAuthProvider('auth0', {
        domain: 'your-domain.auth0.com',
        clientId: 'your-client-id',
        audience: 'your-api-audience',
        cacheLocation: 'sessionstorage'
      });

      // Set up error handling
      this.authProvider.onError((error) => {
        console.error('Auth Error:', error);
        this.handleError(error);
      });

      // Check initial auth state
      const isAuthenticated = await this.authProvider.isAuthenticated();
      this.authStateSubject.next(isAuthenticated);

      if (isAuthenticated) {
        const profile = await this.authProvider.getUserProfile();
        this.userProfileSubject.next(profile);
      }
    } catch (error) {
      console.error('Auth service initialization failed:', error);
    }
  }

  async login() {
    if (this.authProvider) {
      await this.authProvider.login();
    }
  }

  logout() {
    if (this.authProvider) {
      this.authProvider.logout();
      this.authStateSubject.next(false);
      this.userProfileSubject.next(null);
    }
  }

  async getAccessToken(): Promise<string | null> {
    if (this.authProvider) {
      try {
        return await this.authProvider.getAccessToken();
      } catch (error) {
        console.error('Failed to get access token:', error);
        return null;
      }
    }
    return null;
  }

  private handleError(error: any) {
    // Handle specific error types
    switch (error.code) {
      case 'TOKEN_EXPIRED':
        this.refreshTokenOrLogin();
        break;
      case 'NETWORK_ERROR':
        // Show network error notification
        break;
      default:
        // Show generic error notification
        break;
    }
  }

  private async refreshTokenOrLogin() {
    if (this.authProvider) {
      try {
        await this.authProvider.refreshToken();
      } catch (error) {
        // Refresh failed, redirect to login
        this.login();
      }
    }
  }
}
```

### Vue.js Composition API Example

```typescript
import { ref, onMounted } from 'vue';
import GMFCIAMAuth, { AuthProvider, UserProfile } from 'gmf-ciam-sdk';

export function useAuth() {
  const authProvider = ref<AuthProvider | null>(null);
  const isAuthenticated = ref(false);
  const userProfile = ref<UserProfile | null>(null);
  const loading = ref(true);

  onMounted(async () => {
    try {
      const provider = await GMFCIAMAuth.createAuthProvider('auth0', {
        domain: 'your-domain.auth0.com',
        clientId: 'your-client-id',
        audience: 'your-api-audience',
        cacheLocation: 'sessionstorage'
      });

      authProvider.value = provider;

      // Error handling
      provider.onError((error) => {
        console.error('Auth Error:', error);
      });

      // Check authentication
      isAuthenticated.value = await provider.isAuthenticated();
      
      if (isAuthenticated.value) {
        userProfile.value = await provider.getUserProfile();
      }
    } catch (error) {
      console.error('Auth initialization failed:', error);
    } finally {
      loading.value = false;
    }
  });

  const login = async () => {
    if (authProvider.value) {
      await authProvider.value.login();
    }
  };

  const logout = () => {
    if (authProvider.value) {
      authProvider.value.logout();
      isAuthenticated.value = false;
      userProfile.value = null;
    }
  };

  return {
    authProvider,
    isAuthenticated,
    userProfile,
    loading,
    login,
    logout
  };
}
```

## 📘 TypeScript Support

The SDK is written in TypeScript and provides complete type definitions.

### Key Interfaces

```typescript
interface UserProfile {
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
  nickname?: string;
  email_verified?: boolean;
  user_metadata?: Record<string, any>;
  app_metadata?: Record<string, any>;
  [key: string]: any;
}

interface AuthError extends Error {
  name: string;
  code: string;
  details: Record<string, any>;
  timestamp: string;
}

interface AuthStatus {
  authenticated: boolean;
  hasAccessToken: boolean;
  hasRefreshToken: boolean;
  hasUserProfile: boolean;
  tokenExpired: boolean | null;
  expiresAt: string | null;
  lastError?: AuthError | null;
}

interface AuthValidationResult {
  valid: boolean;
  reason?: string;
  error?: string;
}

type ProfileUpdates = Partial<Pick<UserProfile, 
  | 'name' 
  | 'given_name' 
  | 'family_name' 
  | 'nickname'
  | 'user_metadata'
>> & {
  firstname?: string;
  lastname?: string;
};
```

### Type Guards

```typescript
import { AuthError } from 'gmf-ciam-sdk';

function isAuthError(error: any): error is AuthError {
  return error && 
         typeof error.name === 'string' && 
         typeof error.code === 'string' &&
         typeof error.message === 'string';
}

// Usage
try {
  await authProvider.login();
} catch (error) {
  if (isAuthError(error)) {
    console.log('Auth error code:', error.code);
  }
}
```

## 🔄 Migration Guide

### From localStorage to sessionStorage

**Version 2.x Breaking Change:** The SDK now uses `sessionStorage` instead of `localStorage` for security reasons.

**What Changed:**
- Authentication data is now stored in `sessionStorage` (session-only)
- Data is automatically cleared when the browser tab/window is closed
- More secure against persistent storage attacks

**Migration Steps:**
1. Update your configuration to specify `cacheLocation: 'sessionstorage'`
2. Users will need to log in again after the update
3. No code changes required - storage change is automatic

**Before (v1.x):**
```typescript
const config = {
  // ...other config
  cacheLocation: 'localstorage' // Old behavior
};
```

**After (v2.x):**
```typescript
const config = {
  // ...other config
  cacheLocation: 'sessionstorage' // New default
};
```

### Custom Endpoints Migration

If upgrading from a version without custom endpoints:

**Before:**
```typescript
const config = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'your-api-audience'
};
```

**After (Optional - only if you want custom endpoints):**
```typescript
const config = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'your-api-audience',
  customEndpoints: {
    passwordReset: 'https://your-api.com/auth/password-reset',
    passwordChange: 'https://your-api.com/auth/password-change',
    userProfileUpdate: 'https://your-api.com/auth/profile-update'
  }
};
```

## 🔧 Troubleshooting

### Common Issues

#### 1. **CORS Errors**

**Problem:** Browser blocks requests to your API endpoints.

**Solution:**
```typescript
// Ensure your API server allows CORS from your domain
app.use(cors({
  origin: ['http://localhost:4200', 'https://your-app.com'],
  credentials: true
}));
```

#### 2. **Token Expired Errors**

**Problem:** Access token expires and requests fail.

**Solution:**
```typescript
// Set up automatic token refresh
authProvider.onError(async (error) => {
  if (error.code === 'TOKEN_EXPIRED' || error.code === 'INVALID_ACCESS_TOKEN') {
    try {
      await authProvider.refreshToken();
      // Retry the failed operation
    } catch (refreshError) {
      // Refresh failed, redirect to login
      authProvider.login();
    }
  }
});
```

#### 3. **Configuration Errors**

**Problem:** Auth0 configuration is incorrect.

**Solution:**
```typescript
// Verify your Auth0 configuration
const config = {
  domain: 'your-tenant.auth0.com',     // Must match your Auth0 tenant
  clientId: 'your-app-client-id',      // From Auth0 dashboard
  audience: 'https://your-api.com',    // Your API identifier
  redirectUri: window.location.origin  // Must be registered in Auth0
};
```

#### 4. **Custom Endpoint Not Working**

**Problem:** Custom endpoints receive different payload than expected.

**Solution:**
```typescript
// Test your endpoint format first
const testPayload = {
  email: 'test@example.com',
  password: null,
  firstname: null,
  lastname: null,
  usermetadata: null
};

// Use a testing service to verify format
fetch('https://httpbin.org/post', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(testPayload)
}).then(r => r.json()).then(console.log);
```

### Debug Mode

Enable detailed logging for debugging:

```typescript
// Enable debug mode (if available)
localStorage.setItem('gmf-ciam-debug', 'true');

// Or use the built-in debugging methods
const authStatus = authProvider.getAuthStatus();
console.log('Auth Status:', authStatus);

const lastError = authProvider.getLastError();
console.log('Last Error:', lastError);
```

### Testing Utilities

```typescript
// Test HTTP connectivity
async function testConnectivity() {
  try {
    const response = await fetch('https://httpbin.org/get');
    console.log('Network connectivity: OK');
  } catch (error) {
    console.log('Network connectivity: FAILED', error);
  }
}

// Test Auth0 configuration
async function testAuth0Config() {
  try {
    const response = await fetch(`https://${config.domain}/.well-known/openid_configuration`);
    const data = await response.json();
    console.log('Auth0 config valid:', data.issuer);
  } catch (error) {
    console.log('Auth0 config invalid:', error);
  }
}
```

