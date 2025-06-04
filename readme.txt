# GMF CIAM SDK - Angular Integration Documentation

[![Version](https://img.shields.io/npm/v/gmf-ciam-sdk.svg)](https://www.npmjs.com/package/gmf-ciam-sdk)
[![License](https://img.shields.io/npm/l/gmf-ciam-sdk.svg)](https://github.com/your-org/gmf-ciam-sdk/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Angular](https://img.shields.io/badge/Angular-17+-red.svg)](https://angular.io/)

A comprehensive Customer Identity and Access Management (CIAM) SDK specifically designed for Angular applications with Auth0 integration and custom endpoint support.

## 📋 Table of Contents

- [Installation](#installation)
- [Angular Setup](#angular-setup)
- [Configuration](#configuration)
- [Component Integration](#component-integration)
- [Custom Endpoints](#custom-endpoints)
- [Service Implementation](#service-implementation)
- [Error Handling](#error-handling)
- [Testing & Debugging](#testing--debugging)
- [Best Practices](#best-practices)
- [Migration Guide](#migration-guide)
- [Troubleshooting](#troubleshooting)

## 🚀 Installation

### Install the SDK

```bash
npm install gmf-ciam-sdk
```

### Angular Dependencies

Ensure you have the required Angular dependencies:

```bash
npm install @angular/common @angular/forms
```

## ⚙️ Angular Setup

### 1. Update main.ts

```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { Routes } from '@angular/router';
import { importProvidersFrom } from '@angular/core';
import { FormsModule } from '@angular/forms';

const routes: Routes = [
  { path: '', component: AppComponent },
  { path: 'callback', component: AppComponent }, // Auth0 callback route
  { path: '**', redirectTo: '' }
];

bootstrapApplication(AppComponent, {
  providers: [
    provideHttpClient(withInterceptorsFromDi()),
    provideRouter(routes),
    importProvidersFrom(FormsModule)
  ]
}).catch(err => console.error('Application bootstrap failed:', err));
```

### 2. Component Imports

```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule, JsonPipe, DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import GMFCIAMAuth, { AuthProvider, UserProfile, AuthError } from 'GMF-CIAM-sdk';
```

## 🔧 Configuration

### Auth0 Configuration Interface

```typescript
interface Auth0Config {
  domain: string;                    // Your Auth0 domain
  clientId: string;                  // Your Auth0 client ID
  audience: string;                  // Your Auth0 API audience
  redirectUri: string;               // Redirect URI after login
  scope: string;                     // OAuth scopes
  cacheLocation: 'sessionstorage';   // Storage location (secure session-only)
  customEndpoints?: {                // Optional custom API endpoints
    passwordReset?: string;          // Custom password reset endpoint
    passwordChange?: string;         // Custom password change endpoint
    userProfileUpdate?: string;      // Custom profile update endpoint
    getUserProfile?: string;         // Custom get user profile endpoint
  };
}
```

### Basic Configuration

```typescript
auth0Config: Auth0Config = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'https://your-domain.auth0.com/api/v2/',
  redirectUri: window.location.origin,
  scope: 'openid profile email offline_access',
  cacheLocation: 'sessionstorage'
};
```

### Configuration with Custom Endpoints

```typescript
auth0Config: Auth0Config = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'https://your-domain.auth0.com/api/v2/',
  redirectUri: window.location.origin,
  scope: 'openid profile email offline_access',
  cacheLocation: 'sessionstorage',
  
  customEndpoints: {
    passwordReset: 'https://your-api.com/auth/password-reset',
    passwordChange: 'https://your-api.com/auth/password-change',
    userProfileUpdate: 'https://your-api.com/auth/profile-update',
    getUserProfile: 'https://your-api.com/auth/get-user-profile'
  }
};
```

## 🔨 Component Integration

### Complete Angular Component Implementation

```typescript
@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, JsonPipe, DatePipe, FormsModule],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent implements OnInit {
  // Core properties
  authClient: AuthProvider | null = null;
  isAuthenticated: boolean = false;
  isLoading: boolean = true;
  userProfile: UserProfile | null = null;
  currentError: ErrorInfo | null = null;
  
  // Form properties
  resetEmail: string = '';
  showChangePassword: boolean = false;
  oldPassword: string = '';
  newPassword: string = '';
  confirmPassword: string = '';
  
  // Profile update properties
  showUpdateProfile: boolean = false;
  updatedName: string = '';
  updatedNickname: string = '';
  updatedFirstName: string = '';
  updatedLastName: string = '';
  
  // Configuration
  auth0Config: Auth0Config = {
    // Your configuration here
  };

  async ngOnInit() {
    await this.initializeAuth();
    this.setupGlobalErrorListener();
  }

  // Initialize authentication
  async initializeAuth() {
    this.clearError();
    
    try {
      this.authClient = await GMFCIAMAuth.createAuthProvider('auth0', this.auth0Config);
      
      // Set up error handling
      this.authClient.onError((error: AuthError) => {
        this.handleAuthError(error);
      });
      
      // Check authentication status
      this.isAuthenticated = await this.authClient.isAuthenticated();
      
      if (this.isAuthenticated) {
        await this.loadUserData();
      }
    } catch (error) {
      console.error('Auth initialization error:', error);
      this.showError('Authentication system initialization failed', 'error');
    } finally {
      this.isLoading = false;
    }
  }

  // Load user data (uses custom endpoint if configured)
  async loadUserData(): Promise<void> {
    if (!this.authClient) return;
    
    try {
      const profile = await this.authClient.getUserProfile();
      
      if (profile && typeof profile === 'object' && 'sub' in profile) {
        this.userProfile = profile as UserProfile;
        
        // Log which endpoint was used
        const endpointUsed = this.auth0Config.customEndpoints?.getUserProfile ? 
          'custom getUserProfile endpoint' : 'Auth0 /userinfo endpoint';
        console.log(`Profile loaded from: ${endpointUsed}`);
      }
    } catch (error) {
      console.log('Error loading user data, handled by error callback');
    }
  }

  // Authentication methods
  async loginButton(): Promise<void> {
    if (!this.authClient) {
      await this.initializeAuth();
    }
    
    if (this.authClient) {
      this.isLoading = true;
      try {
        await this.authClient.login();
      } catch (error) {
        this.isLoading = false;
      }
    }
  }

  logout(): void {
    if (this.authClient) {
      try {
        this.authClient.logout();
        this.isAuthenticated = false;
        this.userProfile = null;
      } catch (error) {
        console.log('Logout error handled by error callback');
      }
    }
  }

  // Password management
  async resetPassword(): Promise<void> {
    if (!this.resetEmail) {
      this.showError('Please enter an email address', 'warning');
      return;
    }
    
    if (!this.authClient) {
      await this.initializeAuth();
    }
    
    if (this.authClient) {
      this.isLoading = true;
      try {
        const result = await this.authClient.resetPassword(this.resetEmail);
        if (result) {
          this.showError(result, 'success');
          this.resetEmail = '';
        }
      } catch (error) {
        console.log('Password reset error handled by error callback');
      } finally {
        this.isLoading = false;
      }
    }
  }

  async changePassword(): Promise<void> {
    // Validation
    if (!this.oldPassword || !this.newPassword) {
      this.showError('Please fill in both password fields', 'warning');
      return;
    }
    
    if (this.newPassword !== this.confirmPassword) {
      this.showError('New passwords do not match', 'warning');
      return;
    }
    
    if (this.newPassword.length < 8) {
      this.showError('New password must be at least 8 characters long', 'warning');
      return;
    }
    
    if (!this.authClient) return;
    
    this.clearError();
    this.isLoading = true;
    
    try {
      const result = await this.authClient.changePassword(this.oldPassword, this.newPassword);
      if (result) {
        this.showError(result, 'success');
        this.cancelChangePassword();
      }
    } catch (error) {
      console.log('Password change error handled by error callback');
    } finally {
      this.isLoading = false;
    }
  }

  // Profile management
  async updateProfile(): Promise<void> {
    if (!this.updatedName.trim() && !this.updatedNickname.trim() && 
        !this.updatedFirstName.trim() && !this.updatedLastName.trim()) {
      this.showError('Please enter at least one field to update', 'warning');
      return;
    }
    
    if (!this.authClient) return;
    
    this.clearError();
    this.isLoading = true;
    
    const updates: Partial<UserProfile> & { firstname?: string; lastname?: string } = {};
    
    // Standard Auth0 fields
    if (this.updatedName.trim()) updates.name = this.updatedName.trim();
    if (this.updatedNickname.trim()) updates.nickname = this.updatedNickname.trim();
    
    // Custom fields for your API
    if (this.updatedFirstName.trim()) {
      updates.given_name = this.updatedFirstName.trim();
      updates.firstname = this.updatedFirstName.trim();
    }
    if (this.updatedLastName.trim()) {
      updates.family_name = this.updatedLastName.trim();
      updates.lastname = this.updatedLastName.trim();
    }
    
    try {
      const result = await this.authClient.updateUserProfile(updates);
      if (result && typeof result === 'object' && 'sub' in result) {
        this.userProfile = result as UserProfile;
        this.showError('Profile updated successfully!', 'success');
        this.cancelUpdateProfile();
      }
    } catch (error) {
      console.log('Profile update error handled by error callback');
    } finally {
      this.isLoading = false;
    }
  }

  // Error handling
  handleAuthError(error: AuthError) {
    console.error(`[AuthManager] ${error.name}:`, error.message);
    
    switch (error.name) {
      case 'AuthenticationError':
        this.handleAuthenticationError(error);
        break;
      case 'NetworkError':
        this.handleNetworkError(error);
        break;
      case 'TokenError':
        this.handleTokenError(error);
        break;
      case 'ValidationError':
        this.handleValidationError(error);
        break;
      default:
        this.showError(`An unexpected error occurred: ${error.message}`, 'error');
    }
  }

  // Helper methods
  showError(message: string, type: 'error' | 'warning' | 'success' = 'error'): void {
    this.currentError = { message, type, timestamp: new Date() };
    
    if (type === 'success') {
      setTimeout(() => {
        if (this.currentError?.type === 'success') {
          this.clearError();
        }
      }, 5000);
    }
  }

  clearError(): void {
    this.currentError = null;
  }
}
```

## 🔌 Custom Endpoints

### Endpoint Configuration

The SDK supports four custom endpoints that use a standardized payload format:

```typescript
customEndpoints: {
  passwordReset: 'https://your-api.com/auth/password-reset',
  passwordChange: 'https://your-api.com/auth/password-change',
  userProfileUpdate: 'https://your-api.com/auth/profile-update',
  getUserProfile: 'https://your-api.com/auth/get-user-profile'
}
```

### Custom Endpoint Payload Format

All custom endpoints expect this standardized payload:

```typescript
interface CustomEndpointPayload {
  email: string | null;
  password: string | null;
  firstname: string | null;
  lastname: string | null;
  usermetadata: Record<string, any> | null;
}
```

### 1. Password Reset Endpoint

**When Called:** `authClient.resetPassword(email)`

**Payload Format:**
```json
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

### 2. Password Change Endpoint

**When Called:** `authClient.changePassword(oldPassword, newPassword)`

**Payload Format:**
```json
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

### 3. Profile Update Endpoint

**When Called:** `authClient.updateUserProfile(updates)`

**Payload Format:**
```json
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

### 4. Get User Profile Endpoint

**When Called:** `authClient.getUserProfile()`

**Payload Format (POST method):**
```json
{
  "email": "user@example.com",
  "password": null,
  "firstname": null,
  "lastname": null,
  "usermetadata": null
}
```

**Alternative: GET method (remove body)**
```http
GET /auth/get-user-profile
Authorization: Bearer <access-token>
```

**Expected Response:**
```json
{
  "sub": "auth0|user-id",
  "email": "user@example.com",
  "given_name": "John",
  "family_name": "Doe",
  "name": "John Doe",
  "picture": "https://example.com/profile.jpg",
  "email_verified": true,
  "user_metadata": {
    "preferences": {
      "theme": "dark"
    }
  },
  "lastLoginDate": "2025-06-04T10:30:00Z",
  "accountStatus": "active",
  "permissions": ["read", "write"]
}
```

### Fallback Behavior

- **If custom endpoint is configured:** Uses your API
- **If not configured:** Falls back to Auth0 standard APIs
- **No code changes required:** Existing `getUserProfile()` calls work seamlessly

## 🏗️ Service Implementation

### Create an Angular Authentication Service

```typescript
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import GMFCIAMAuth, { AuthProvider, UserProfile, AuthError } from 'GMF-CIAM-sdk';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private authProvider: AuthProvider | null = null;
  private authStateSubject = new BehaviorSubject<boolean>(false);
  private userProfileSubject = new BehaviorSubject<UserProfile | null>(null);
  private loadingSubject = new BehaviorSubject<boolean>(true);
  private errorSubject = new BehaviorSubject<AuthError | null>(null);

  // Public observables
  public authState$: Observable<boolean> = this.authStateSubject.asObservable();
  public userProfile$: Observable<UserProfile | null> = this.userProfileSubject.asObservable();
  public loading$: Observable<boolean> = this.loadingSubject.asObservable();
  public error$: Observable<AuthError | null> = this.errorSubject.asObservable();

  private auth0Config = {
    domain: 'your-domain.auth0.com',
    clientId: 'your-client-id',
    audience: 'https://your-domain.auth0.com/api/v2/',
    redirectUri: window.location.origin,
    scope: 'openid profile email offline_access',
    cacheLocation: 'sessionstorage' as const,
    customEndpoints: {
      passwordReset: 'https://your-api.com/auth/password-reset',
      passwordChange: 'https://your-api.com/auth/password-change',
      userProfileUpdate: 'https://your-api.com/auth/profile-update',
      getUserProfile: 'https://your-api.com/auth/get-user-profile'
    }
  };

  async initialize(): Promise<void> {
    try {
      this.authProvider = await GMFCIAMAuth.createAuthProvider('auth0', this.auth0Config);

      // Set up error handling
      this.authProvider.onError((error: AuthError) => {
        console.error('Auth Error:', error);
        this.errorSubject.next(error);
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
      this.errorSubject.next(error as AuthError);
    } finally {
      this.loadingSubject.next(false);
    }
  }

  async login(): Promise<void> {
    if (this.authProvider) {
      this.loadingSubject.next(true);
      try {
        await this.authProvider.login();
      } catch (error) {
        this.loadingSubject.next(false);
        throw error;
      }
    }
  }

  logout(): void {
    if (this.authProvider) {
      this.authProvider.logout();
      this.authStateSubject.next(false);
      this.userProfileSubject.next(null);
    }
  }

  async resetPassword(email: string): Promise<string> {
    if (!this.authProvider) {
      throw new Error('Auth provider not initialized');
    }
    return this.authProvider.resetPassword(email);
  }

  async changePassword(oldPassword: string, newPassword: string): Promise<string> {
    if (!this.authProvider) {
      throw new Error('Auth provider not initialized');
    }
    return this.authProvider.changePassword(oldPassword, newPassword);
  }

  async updateUserProfile(updates: Partial<UserProfile>): Promise<UserProfile> {
    if (!this.authProvider) {
      throw new Error('Auth provider not initialized');
    }
    
    const updatedProfile = await this.authProvider.updateUserProfile(updates);
    this.userProfileSubject.next(updatedProfile);
    return updatedProfile;
  }

  async refreshProfile(): Promise<UserProfile> {
    if (!this.authProvider) {
      throw new Error('Auth provider not initialized');
    }
    
    const profile = await this.authProvider.getUserProfile(true); // Force refresh
    this.userProfileSubject.next(profile);
    return profile;
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

  clearError(): void {
    this.errorSubject.next(null);
    if (this.authProvider) {
      this.authProvider.clearError();
    }
  }

  private handleError(error: AuthError): void {
    switch (error.code) {
      case 'TOKEN_EXPIRED':
      case 'INVALID_REFRESH_TOKEN':
        this.refreshTokenOrLogin();
        break;
      case 'NOT_AUTHENTICATED':
        this.authStateSubject.next(false);
        this.userProfileSubject.next(null);
        break;
      default:
        // Handle other errors as needed
        break;
    }
  }

  private async refreshTokenOrLogin(): Promise<void> {
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

### Using the Service in Components

```typescript
@Component({
  selector: 'app-profile',
  template: `
    <div *ngIf="authService.loading$ | async">Loading...</div>
    
    <div *ngIf="authService.error$ | async as error" class="error">
      {{ error.message }}
      <button (click)="authService.clearError()">Clear</button>
    </div>
    
    <div *ngIf="authService.authState$ | async; else loginTemplate">
      <div *ngIf="authService.userProfile$ | async as profile">
        <h2>Welcome, {{ profile.name }}!</h2>
        <p>Email: {{ profile.email }}</p>
        
        <button (click)="refreshProfile()">Refresh Profile</button>
        <button (click)="authService.logout()">Logout</button>
      </div>
    </div>
    
    <ng-template #loginTemplate>
      <button (click)="authService.login()">Login</button>
    </ng-template>
  `
})
export class ProfileComponent {
  constructor(public authService: AuthService) {}

  async ngOnInit() {
    await this.authService.initialize();
  }

  async refreshProfile() {
    try {
      await this.authService.refreshProfile();
    } catch (error) {
      console.error('Failed to refresh profile:', error);
    }
  }
}
```

## ⚠️ Error Handling

### Error Types and Handling

```typescript
interface ErrorInfo {
  message: string;
  type: 'error' | 'warning' | 'success';
  timestamp: Date;
}

// Comprehensive error handling
handleAuthError(error: AuthError) {
  switch (error.name) {
    case 'AuthenticationError':
      switch (error.code) {
        case 'NOT_AUTHENTICATED':
          this.showError('Please log in to access this feature', 'warning');
          this.isAuthenticated = false;
          break;
        case 'INCORRECT_PASSWORD':
          this.showError('The password you entered is incorrect', 'error');
          break;
        case 'USER_NOT_FOUND':
          this.showError('No account found with this email address', 'error');
          break;
        default:
          this.showError(`Authentication failed: ${error.message}`, 'error');
      }
      break;

    case 'TokenError':
      switch (error.code) {
        case 'TOKEN_EXPIRED':
        case 'INVALID_REFRESH_TOKEN':
          this.showError('Your session has expired. Please log in again', 'warning');
          this.isAuthenticated = false;
          this.userProfile = null;
          break;
        case 'NO_MANAGEMENT_TOKEN':
          this.showError('This feature requires server-side authentication setup', 'warning');
          break;
        default:
          this.showError(`Token error: ${error.message}`, 'error');
      }
      break;

    case 'NetworkError':
      if (error.details?.status >= 500) {
        this.showError('Service temporarily unavailable. Please try again later', 'warning');
      } else {
        this.showError('Network error. Please check your connection', 'error');
      }
      break;

    case 'ValidationError':
      switch (error.code) {
        case 'INVALID_EMAIL_FORMAT':
          this.showError('Please enter a valid email address', 'warning');
          break;
        case 'PASSWORD_TOO_SHORT':
          this.showError('Password must be at least 8 characters long', 'warning');
          break;
        default:
          this.showError(`Validation error: ${error.message}`, 'warning');
      }
      break;

    default:
      this.showError(`An unexpected error occurred: ${error.message}`, 'error');
  }
}
```

### Error Display in Templates

```html
<!-- Error Display Component -->
<div *ngIf="currentError" [class]="getErrorClass()" class="error-container">
  <span>{{ currentError.message }}</span>
  <button (click)="clearError()" class="close-button">&times;</button>
  <div class="clear"></div>
  <small class="timestamp">{{ currentError.timestamp | date:'medium' }}</small>
</div>
```

```css
/* Error styling */
.error-container {
  margin-bottom: 20px;
  padding: 10px;
  border-radius: 4px;
  position: relative;
}

.error-message {
  background-color: #f8d7da;
  color: #721c24;
  border: 1px solid #f5c6cb;
}

.warning-message {
  background-color: #fff3cd;
  color: #856404;
  border: 1px solid #ffeaa7;
}

.success-message {
  background-color: #d4edda;
  color: #155724;
  border: 1px solid #c3e6cb;
}

.close-button {
  float: right;
  background: none;
  border: none;
  font-size: 18px;
  cursor: pointer;
}

.timestamp {
  opacity: 0.7;
  font-size: 12px;
}
```

## 🧪 Testing & Debugging

### Built-in Testing Methods

```typescript
// Test HTTP connectivity
async testHttpSetup(): Promise<void> {
  try {
    const response = await fetch('https://jsonplaceholder.typicode.com/posts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'Test', body: 'Testing', userId: 1 })
    });
    
    if (response.ok) {
      this.showError('✅ HTTP requests are working correctly!', 'success');
    }
  } catch (error) {
    this.showError('❌ HTTP setup issue - check network/CORS', 'error');
  }
}

// Test custom endpoint payload format
async testCustomEndpointFormat(): Promise<void> {
  try {
    const payload = {
      email: 'test@example.com',
      password: null,
      firstname: null,
      lastname: null,
      usermetadata: null
    };
    
    const response = await fetch('https://httpbin.org/post', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-token'
      },
      body: JSON.stringify(payload)
    });
    
    if (response.ok) {
      const data = await response.json();
      console.log('Payload format test:', data.json);
      this.showError('✅ Custom endpoint format is correct!', 'success');
    }
  } catch (error) {
    this.showError('❌ Custom endpoint format test failed', 'error');
  }
}

// Test custom getUserProfile endpoint
async testCustomGetUserProfile(): Promise<void> {
  if (!this.isAuthenticated) {
    this.showError('Please log in first', 'warning');
    return;
  }

  if (!this.auth0Config.customEndpoints?.getUserProfile) {
    this.showError('Custom getUserProfile endpoint not configured', 'warning');
    return;
  }

  try {
    // Force refresh to test custom endpoint
    const profile = await this.authClient?.getUserProfile(true);
    console.log('Custom getUserProfile result:', profile);
    this.showError('✅ Custom getUserProfile endpoint working!', 'success');
  } catch (error) {
    this.showError('❌ Custom getUserProfile test failed', 'error');
  }
}

// Debug methods
getLastSDKError(): string {
  if (!this.authClient) return 'Auth client not initialized';
  
  const error = this.authClient.getLastError();
  return error ? JSON.stringify(error, null, 2) : 'No recent errors';
}

getAuthStatus(): string {
  if (!this.authClient) return 'Auth client not initialized';
  
  const status = this.authClient.getAuthStatus();
  return JSON.stringify(status, null, 2);
}
```

### Testing Template Integration

```html
<!-- API Testing Section -->
<div class="testing-section" *ngIf="isAuthenticated">
  <h3>🧪 API Testing & Diagnostics</h3>
  
  <div class="test-buttons">
    <button (click)="testHttpSetup()" class="test-btn">Test HTTP Setup</button>
    <button (click)="testCustomEndpointFormat()" class="test-btn">Test Payload Format</button>
    <button (click)="testCustomGetUserProfile()" 
            [disabled]="!auth0Config.customEndpoints?.getUserProfile"
            class="test-btn">Test Custom getUserProfile</button>
    <button (click)="checkEndpointConfiguration()" class="test-btn">Check Endpoints</button>
  </div>
  
  <!-- Debug Information -->
  <details class="debug-section">
    <summary>🔧 Debug Information</summary>
    
    <div class="debug-content">
      <h4>Authentication Status</h4>
      <pre>{{ getAuthStatus() }}</pre>
      
      <h4>Last SDK Error</h4>
      <pre>{{ getLastSDKError() }}</pre>
      
      <h4>Custom Endpoints Configuration</h4>
      <div class="endpoint-status">
        <div class="endpoint-item">
          <strong>Password Reset:</strong>
          <span [class]="auth0Config.customEndpoints?.passwordReset ? 'configured' : 'not-configured'">
            {{ auth0Config.customEndpoints?.passwordReset || 'Not configured' }}
          </span>
        </div>
        <div class="endpoint-item">
          <strong>Password Change:</strong>
          <span [class]="auth0Config.customEndpoints?.passwordChange ? 'configured' : 'not-configured'">
            {{ auth0Config.customEndpoints?.passwordChange || 'Not configured' }}
          </span>
        </div>
        <div class="endpoint-item">
          <strong>Profile Update:</strong>
          <span [class]="auth0Config.customEndpoints?.userProfileUpdate ? 'configured' : 'not-configured'">
            {{ auth0Config.customEndpoints?.userProfileUpdate || 'Not configured' }}
          </span>
        </div>
        <div class="endpoint-item">
          <strong>Get User Profile:</strong>
          <span [class]="auth0Config.customEndpoints?.getUserProfile ? 'configured' : 'not-configured'">
            {{ auth0Config.customEndpoints?.getUserProfile || 'Not configured' }}
          </span>
        </div>
      </div>
    </div>
  </details>
</div>
```

## 📘 Best Practices

### 1. Security Best Practices

#### Use sessionStorage (Not localStorage)
```typescript
auth0Config: Auth0Config = {
  // Always use sessionStorage for security
  cacheLocation: 'sessionstorage',
  // ... other config
};
```

**Why sessionStorage?**
- Data is cleared when tab/window closes
- More secure against persistent storage attacks
- Prevents authentication data from persisting across browser sessions

#### Proper Token Handling
```typescript
async getAccessToken(): Promise<string | null> {
  try {
    const token = await this.authClient?.getAccessToken();
    
    // Never log tokens in production
    if (environment.production) {
      console.log('Token acquired'); // Don't log the actual token
    } else {
      console.log('Token:', token?.substring(0, 20) + '...');
    }
    
    return token || null;
  } catch (error) {
    console.error('Failed to get access token:', error);
    return null;
  }
}
```

#### Environment-Specific Configuration
```typescript
// environments/environment.ts
export const environment = {
  production: false,
  auth0: {
    domain: 'dev-domain.auth0.com',
    clientId: 'dev-client-id',
    customEndpoints: {
      passwordReset: 'https://dev-api.com/auth/password-reset',
      // ... other dev endpoints
    }
  }
};

// environments/environment.prod.ts
export const environment = {
  production: true,
  auth0: {
    domain: 'prod-domain.auth0.com',
    clientId: 'prod-client-id',
    customEndpoints: {
      passwordReset: 'https://api.com/auth/password-reset',
      // ... other prod endpoints
    }
  }
};

// Component usage
auth0Config: Auth0Config = {
  ...environment.auth0,
  redirectUri: window.location.origin,
  scope: 'openid profile email offline_access',
  cacheLocation: 'sessionstorage'
};
```

### 2. Error Handling Best Practices

#### Centralized Error Management
```typescript
@Injectable({
  providedIn: 'root'
})
export class ErrorHandlingService {
  private errorSubject = new BehaviorSubject<ErrorInfo | null>(null);
  public error$ = this.errorSubject.asObservable();

  handleAuthError(error: AuthError): void {
    const errorInfo: ErrorInfo = {
      message: this.getHumanReadableMessage(error),
      type: this.getErrorType(error),
      timestamp: new Date()
    };

    this.errorSubject.next(errorInfo);

    // Auto-clear success messages
    if (errorInfo.type === 'success') {
      setTimeout(() => this.clearError(), 5000);
    }
  }

  private getHumanReadableMessage(error: AuthError): string {
    const messages: Record<string, string> = {
      'NOT_AUTHENTICATED': 'Please log in to continue',
      'TOKEN_EXPIRED': 'Your session has expired. Please log in again',
      'INCORRECT_PASSWORD': 'The password you entered is incorrect',
      'INVALID_EMAIL_FORMAT': 'Please enter a valid email address',
      'PASSWORD_TOO_SHORT': 'Password must be at least 8 characters long',
      'NETWORK_ERROR': 'Unable to connect to the server. Please check your internet connection'
    };

    return messages[error.code] || error.message || 'An unexpected error occurred';
  }

  private getErrorType(error: AuthError): 'error' | 'warning' | 'success' {
    const warningCodes = ['NOT_AUTHENTICATED', 'TOKEN_EXPIRED', 'NO_MANAGEMENT_TOKEN'];
    return warningCodes.includes(error.code) ? 'warning' : 'error';
  }

  clearError(): void {
    this.errorSubject.next(null);
  }
}
```

### 3. Performance Optimization

#### Lazy Loading and Async Initialization
```typescript
@Component({
  selector: 'app-auth-guard',
  template: `
    <div *ngIf="loading$ | async" class="loading-spinner">
      <div class="spinner"></div>
      <p>Initializing authentication...</p>
    </div>
    
    <ng-container *ngIf="!(loading$ | async)">
      <router-outlet *ngIf="authState$ | async; else loginTemplate"></router-outlet>
      
      <ng-template #loginTemplate>
        <app-login></app-login>
      </ng-template>
    </ng-container>
  `
})
export class AuthGuardComponent implements OnInit {
  authState$ = this.authService.authState$;
  loading$ = this.authService.loading$;

  constructor(private authService: AuthService) {}

  async ngOnInit() {
    // Initialize only when component loads
    await this.authService.initialize();
  }
}
```

#### Efficient Token Management
```typescript
@Injectable({
  providedIn: 'root'
})
export class TokenService {
  private tokenCache: { token: string; expiresAt: number } | null = null;

  async getValidToken(): Promise<string | null> {
    // Check cache first
    if (this.tokenCache && this.tokenCache.expiresAt > Date.now() + 60000) { // 1 min buffer
      return this.tokenCache.token;
    }

    // Get fresh token
    try {
      const token = await this.authService.getAccessToken();
      if (token) {
        // Cache token with expiration
        const payload = JSON.parse(atob(token.split('.')[1]));
        this.tokenCache = {
          token,
          expiresAt: payload.exp * 1000
        };
      }
      return token;
    } catch (error) {
      this.tokenCache = null;
      return null;
    }
  }

  clearTokenCache(): void {
    this.tokenCache = null;
  }
}
```

### 4. Testing Best Practices

#### Unit Testing with Jasmine/Jest
```typescript
describe('AuthService', () => {
  let service: AuthService;
  let mockAuthProvider: jasmine.SpyObj<AuthProvider>;

  beforeEach(() => {
    const spy = jasmine.createSpyObj('AuthProvider', [
      'login', 'logout', 'isAuthenticated', 'getUserProfile', 
      'resetPassword', 'changePassword', 'updateUserProfile'
    ]);

    TestBed.configureTestingModule({
      providers: [
        AuthService,
        { provide: AuthProvider, useValue: spy }
      ]
    });

    service = TestBed.inject(AuthService);
    mockAuthProvider = TestBed.inject(AuthProvider) as jasmine.SpyObj<AuthProvider>;
  });

  it('should initialize successfully', async () => {
    mockAuthProvider.isAuthenticated.and.returnValue(Promise.resolve(true));
    mockAuthProvider.getUserProfile.and.returnValue(Promise.resolve({
      sub: 'test-user',
      email: 'test@example.com'
    }));

    await service.initialize();

    expect(service.authState$.value).toBe(true);
    expect(service.userProfile$.value).toEqual(jasmine.objectContaining({
      sub: 'test-user',
      email: 'test@example.com'
    }));
  });

  it('should handle login errors gracefully', async () => {
    const error = new Error('Login failed') as AuthError;
    error.code = 'LOGIN_ERROR';
    error.name = 'AuthenticationError';

    mockAuthProvider.login.and.returnValue(Promise.reject(error));

    await expectAsync(service.login()).toBeRejected();
    expect(service.error$.value).toEqual(jasmine.objectContaining({
      message: jasmine.any(String)
    }));
  });
});
```

#### Integration Testing
```typescript
describe('AuthComponent Integration', () => {
  let component: AuthComponent;
  let fixture: ComponentFixture<AuthComponent>;
  let authService: AuthService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AuthComponent, CommonModule, FormsModule],
      providers: [AuthService]
    }).compileComponents();

    fixture = TestBed.createComponent(AuthComponent);
    component = fixture.componentInstance;
    authService = TestBed.inject(AuthService);
  });

  it('should display login form when not authenticated', () => {
    authService.authStateSubject.next(false);
    fixture.detectChanges();

    const loginButton = fixture.debugElement.query(By.css('[data-testid="login-button"]'));
    expect(loginButton).toBeTruthy();
  });

  it('should display user profile when authenticated', async () => {
    const mockProfile = { sub: 'test-user', name: 'Test User', email: 'test@example.com' };
    
    authService.authStateSubject.next(true);
    authService.userProfileSubject.next(mockProfile);
    fixture.detectChanges();

    const profileSection = fixture.debugElement.query(By.css('[data-testid="user-profile"]'));
    expect(profileSection).toBeTruthy();
    expect(profileSection.nativeElement.textContent).toContain('Test User');
  });
});
```

## 🔄 Migration Guide

### From localStorage to sessionStorage

#### What Changed in v2.x
- **Storage Location**: Authentication data now uses `sessionStorage` instead of `localStorage`
- **Session Behavior**: Data is cleared when browser tab/window closes
- **Security**: Enhanced protection against persistent storage attacks

#### Migration Steps

1. **Update Configuration**
```typescript
// OLD (v1.x)
auth0Config = {
  // ... other config
  cacheLocation: 'localstorage' // Remove this
};

// NEW (v2.x)
auth0Config = {
  // ... other config
  cacheLocation: 'sessionstorage' // Add this
};
```

2. **User Impact**
- Users will need to log in again after the update
- Sessions won't persist across browser restarts
- More secure authentication experience

3. **Code Changes**
```typescript
// No code changes required for basic functionality
// All methods work the same way:
await this.authClient.login();
await this.authClient.getUserProfile();
await this.authClient.logout();
```

### Adding Custom Endpoints to Existing Implementation

#### Step 1: Update Configuration
```typescript
// Add custom endpoints to existing config
auth0Config: Auth0Config = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'https://your-domain.auth0.com/api/v2/',
  redirectUri: window.location.origin,
  scope: 'openid profile email offline_access',
  cacheLocation: 'sessionstorage',
  
  // ADD THESE CUSTOM ENDPOINTS
  customEndpoints: {
    passwordReset: 'https://your-api.com/auth/password-reset',
    passwordChange: 'https://your-api.com/auth/password-change',
    userProfileUpdate: 'https://your-api.com/auth/profile-update',
    getUserProfile: 'https://your-api.com/auth/get-user-profile'
  }
};
```

#### Step 2: No Code Changes Required
```typescript
// These methods automatically use custom endpoints when configured:
await this.authClient.resetPassword(email);           // Uses custom endpoint
await this.authClient.changePassword(old, new);       // Uses custom endpoint  
await this.authClient.updateUserProfile(updates);     // Uses custom endpoint
await this.authClient.getUserProfile();               // Uses custom endpoint

// If custom endpoints are not configured, falls back to Auth0 APIs
```

#### Step 3: Test Implementation
```typescript
// Add testing methods to verify custom endpoints
async testCustomEndpoints(): Promise<void> {
  const endpoints = this.auth0Config.customEndpoints;
  const configuredCount = endpoints ? Object.values(endpoints).filter(Boolean).length : 0;
  
  console.log(`Custom endpoints configured: ${configuredCount}/4`);
  
  if (configuredCount === 4) {
    this.showError('✅ All custom endpoints configured!', 'success');
  } else {
    this.showError(`⚠️ ${configuredCount}/4 endpoints configured`, 'warning');
  }
}
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. "Auth client not initialized" Error

**Problem**: Trying to use auth methods before initialization
```typescript
// ❌ WRONG - Using auth before initialization
async ngOnInit() {
  await this.authClient.login(); // Error: authClient is null
}
```

**Solution**: Always initialize first
```typescript
// ✅ CORRECT - Initialize before use
async ngOnInit() {
  await this.initializeAuth();
  // Now authClient is ready to use
}

async initializeAuth() {
  this.authClient = await GMFCIAMAuth.createAuthProvider('auth0', this.auth0Config);
  // Set up error handling, check auth state, etc.
}
```

#### 2. CORS Errors with Custom Endpoints

**Problem**: Browser blocks requests to custom API endpoints

**Solution**: Configure CORS on your server
```javascript
// Express.js example
app.use(cors({
  origin: ['http://localhost:4200', 'https://your-app.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

#### 3. Custom Endpoints Not Being Called

**Problem**: SDK still using Auth0 endpoints instead of custom ones

**Check**: Endpoint URL format
```typescript
// ❌ WRONG - Missing protocol or invalid URL
customEndpoints: {
  passwordReset: 'your-api.com/auth/password-reset',      // Missing https://
  passwordChange: 'https://your-api.com/auth/password-change'  // ✅ Correct
}
```

**Solution**: Use full URLs with protocol
```typescript
// ✅ CORRECT - Full URLs with https://
customEndpoints: {
  passwordReset: 'https://your-api.com/auth/password-reset',
  passwordChange: 'https://your-api.com/auth/password-change',
  userProfileUpdate: 'https://your-api.com/auth/profile-update',
  getUserProfile: 'https://your-api.com/auth/get-user-profile'
}
```

#### 4. Token Expiry Issues

**Problem**: Getting "Token expired" errors frequently

**Solution**: Implement automatic token refresh
```typescript
// Set up automatic token refresh
this.authClient.onError(async (error: AuthError) => {
  if (error.code === 'TOKEN_EXPIRED' || error.code === 'INVALID_ACCESS_TOKEN') {
    try {
      await this.authClient.refreshToken();
      // Retry the failed operation
      this.retryFailedOperation();
    } catch (refreshError) {
      // Refresh failed, redirect to login
      this.login();
    }
  }
});
```

#### 5. Profile Not Updating After Changes

**Problem**: Profile changes don't reflect in the UI

**Solution**: Force refresh after updates
```typescript
async updateProfile(): Promise<void> {
  try {
    const result = await this.authClient.updateUserProfile(updates);
    
    // Force refresh to get latest data
    this.userProfile = await this.authClient.getUserProfile(true);
    
    this.showError('Profile updated successfully!', 'success');
  } catch (error) {
    // Handle error
  }
}
```

#### 6. Testing Endpoint Connectivity

**Problem**: Unsure if custom endpoints are working

**Solution**: Use built-in testing methods
```typescript
// Test HTTP connectivity
async testEndpointConnectivity(): Promise<void> {
  const endpoints = [
    { name: 'Password Reset', url: this.auth0Config.customEndpoints?.passwordReset },
    { name: 'Password Change', url: this.auth0Config.customEndpoints?.passwordChange },
    { name: 'Profile Update', url: this.auth0Config.customEndpoints?.userProfileUpdate },
    { name: 'Get User Profile', url: this.auth0Config.customEndpoints?.getUserProfile }
  ];

  for (const endpoint of endpoints) {
    if (!endpoint.url) {
      console.log(`⚠️ ${endpoint.name}: Not configured`);
      continue;
    }

    try {
      const response = await fetch(endpoint.url, {
        method: 'OPTIONS',
        headers: { 'Content-Type': 'application/json' }
      });
      
      console.log(`✅ ${endpoint.name}: Reachable (${response.status})`);
    } catch (error) {
      console.log(`❌ ${endpoint.name}: Not reachable`, error);
    }
  }
}
```

### Debug Information

#### Enable Debug Logging
```typescript
// Enable detailed logging for debugging
async initializeAuth() {
  try {
    this.authClient = await GMFCIAMAuth.createAuthProvider('auth0', this.auth0Config);
    
    // Log configuration (remove in production)
    if (!environment.production) {
      console.log('Auth0 Config:', {
        domain: this.auth0Config.domain,
        clientId: this.auth0Config.clientId.substring(0, 8) + '...',
        customEndpoints: this.auth0Config.customEndpoints
      });
    }
    
    // Enhanced error logging
    this.authClient.onError((error: AuthError) => {
      console.group(`🚨 Auth Error: ${error.name}`);
      console.log('Code:', error.code);
      console.log('Message:', error.message);
      console.log('Details:', error.details);
      console.log('Timestamp:', error.timestamp);
      console.groupEnd();
      
      this.handleAuthError(error);
    });
    
  } catch (error) {
    console.error('❌ Auth initialization failed:', error);
  }
}
```

#### Check Authentication State
```typescript
// Debug authentication state
getDetailedAuthStatus(): any {
  if (!this.authClient) {
    return { error: 'Auth client not initialized' };
  }

  const status = this.authClient.getAuthStatus();
  const lastError = this.authClient.getLastError();
  
  return {
    ...status,
    lastError: lastError ? {
      name: lastError.name,
      code: lastError.code,
      message: lastError.message,
      timestamp: lastError.timestamp
    } : null,
    configuredEndpoints: Object.keys(this.auth0Config.customEndpoints || {}),
    currentUrl: window.location.href
  };
}
```

