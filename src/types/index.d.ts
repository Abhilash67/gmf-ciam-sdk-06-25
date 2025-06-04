// src/types/index.d.ts - Updated with getUserProfile endpoint support
export interface CustomEndpoints {
  passwordReset?: string;
  passwordChange?: string;
  userProfileUpdate?: string;
  getUserProfile?: string; // Custom getUserProfile endpoint
}

export interface AuthConfig {
  domain: string;
  clientId: string;
  audience?: string;
  redirectUri?: string;
  scope?: string;
  responseType?: string;
  cacheLocation?: string;
  clientSecret?: string; // For server-side operations
  managementApiAudience?: string;
  customEndpoints?: CustomEndpoints; // Enhanced with getUserProfile
}

export interface OktaConfig {
  orgUrl: string;
  clientId: string;
  redirectUri?: string;
  scopes?: string[];
}

export interface UserProfile {
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  website?: string;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  address?: any;
  user_metadata?: Record<string, any>;
  app_metadata?: Record<string, any>;
  [key: string]: any;
}

// Error types
export interface AuthError extends Error {
  name: string;
  code: string;
  details: Record<string, any>;
  timestamp: string;
}

export type ErrorType = 
  | 'AuthenticationError'
  | 'ConfigurationError'
  | 'NetworkError'
  | 'TokenError'
  | 'ValidationError'
  | 'OperationError';

export type ErrorCallback = (error: AuthError) => void;

// Auth status and validation types
export interface AuthStatus {
  authenticated: boolean;
  hasAccessToken: boolean;
  hasRefreshToken: boolean;
  hasUserProfile: boolean;
  tokenExpired: boolean | null;
  expiresAt: string | null;
  lastError?: AuthError | null;
}

export interface AuthValidationResult {
  valid: boolean;
  reason?: string;
  error?: string;
}

// Profile update types - Updated to include firstname/lastname
export type ProfileUpdates = Partial<Pick<UserProfile, 
  | 'name' 
  | 'given_name' 
  | 'family_name' 
  | 'middle_name' 
  | 'nickname'
  | 'preferred_username' 
  | 'profile' 
  | 'picture' 
  | 'website' 
  | 'gender'
  | 'birthdate' 
  | 'zoneinfo' 
  | 'locale' 
  | 'phone_number' 
  | 'address'
  | 'user_metadata' 
  | 'app_metadata'
>> & {
  firstname?: string; // Additional field for custom endpoint
  lastname?: string;  // Additional field for custom endpoint
};

// Custom endpoint payload interfaces
export interface CustomPasswordResetPayload {
  email: string;
  password: null;
  firstname: null;
  lastname: null;
  usermetadata: null;
}

export interface CustomPasswordChangePayload {
  email: string;
  password: string;
  firstname: string | null;
  lastname: string | null;
  usermetadata: Record<string, any> | null;
}

export interface CustomUserProfileUpdatePayload {
  email: string;
  password: null;
  firstname: string | null;
  lastname: string | null;
  usermetadata: Record<string, any> | null;
}

// Custom getUserProfile payload interface
export interface CustomGetUserProfilePayload {
  email: string;
  password: null;
  firstname: null;
  lastname: null;
  usermetadata: null;
}

// Custom getUserProfile response interface
export interface CustomGetUserProfileResponse extends UserProfile {
  // Your API might return additional fields
  // Add any custom fields your API returns here
  lastLoginDate?: string;
  accountStatus?: string;
  permissions?: string[];
  // ... any other custom fields your API returns
}

export interface AuthProvider {
  // Core authentication methods
  login(): Promise<void>;
  logout(): void;
  getUserProfile(forceRefresh?: boolean): Promise<UserProfile>;
  isAuthenticated(): boolean | Promise<boolean>;
  getAccessToken(): string | Promise<string>;
  refreshToken(): Promise<boolean>;
  
  // Password management
  resetPassword(email: string): Promise<string>;
  changePassword(oldPassword: string, newPassword: string): Promise<string>;
  
  // Profile management
  getDetailedUserProfile(): Promise<UserProfile>;
  updateUserProfile(updates: ProfileUpdates): Promise<UserProfile>;
  
  // Custom getUserProfile method for testing custom endpoint
  testCustomGetUserProfile?(): Promise<UserProfile>;
  
  // Error handling methods
  createError(type: ErrorType, message: string, code: string, details?: Record<string, any>): AuthError;
  createAuthError(message: string, code?: string, details?: Record<string, any>): AuthError;
  createConfigError(message: string, code?: string, details?: Record<string, any>): AuthError;
  createNetworkError(message: string, code?: string, details?: Record<string, any>): AuthError;
  createTokenError(message: string, code?: string, details?: Record<string, any>): AuthError;
  createValidationError(message: string, code?: string, details?: Record<string, any>): AuthError;
  
  getLastError(): AuthError | null;
  clearError(): void;
  onError(callback: ErrorCallback): void;
  removeErrorCallback(callback: ErrorCallback): void;
  
  // Utility methods
  handleAsync<T>(operation: () => Promise<T>, errorContext?: string): Promise<T>;
  validateAuthState(): Promise<AuthValidationResult>;
  getAuthStatus(): AuthStatus;
}

export interface GMFCIAMAuth {
  createAuthProvider(type: 'auth0', config: AuthConfig): Promise<AuthProvider>;
}

// Error code type - using string literal union instead of const object
export type AuthErrorCode = 
  // Configuration errors
  | 'MISSING_CONFIG'
  | 'INCOMPLETE_CONFIG'
  | 'INVALID_DOMAIN'
  | 'LOGIN_CONFIG_ERROR'
  | 'MISSING_CUSTOM_ENDPOINT' // For missing custom endpoint
  
  // Authentication errors
  | 'NOT_AUTHENTICATED'
  | 'INVALID_STATE'
  | 'MISSING_AUTH_CODE'
  | 'INCORRECT_PASSWORD'
  | 'USER_NOT_FOUND'
  | 'INSUFFICIENT_PERMISSIONS'
  | 'INVALID_PROFILE_DATA'
  
  // Token errors
  | 'TOKEN_EXPIRED'
  | 'INVALID_REFRESH_TOKEN'
  | 'NO_REFRESH_TOKEN'
  | 'MISSING_REFRESH_TOKEN'
  | 'INVALID_ACCESS_TOKEN'
  | 'NO_ACCESS_TOKEN'
  | 'MISSING_ACCESS_TOKEN'
  | 'NO_MANAGEMENT_TOKEN'
  | 'INVALID_MANAGEMENT_TOKEN'
  | 'INVALID_REFRESH_RESPONSE'
  | 'INVALID_MGMT_TOKEN_RESPONSE'
  
  // Network errors
  | 'NETWORK_ERROR'
  | 'TOKEN_EXCHANGE_ERROR'
  | 'TOKEN_REFRESH_ERROR'
  | 'PASSWORD_RESET_ERROR'
  | 'PASSWORD_VERIFY_ERROR'
  | 'PASSWORD_UPDATE_ERROR'
  | 'PROFILE_FETCH_ERROR'
  | 'DETAILED_PROFILE_ERROR'
  | 'PROFILE_UPDATE_ERROR'
  | 'CUSTOM_PROFILE_FETCH_ERROR' // New error code for custom getUserProfile
  | 'MGMT_TOKEN_ERROR'
  | 'MGMT_API_ERROR'
  
  // Validation errors
  | 'MISSING_EMAIL'
  | 'INVALID_EMAIL_FORMAT'
  | 'MISSING_PASSWORDS'
  | 'INVALID_PASSWORD_TYPE'
  | 'PASSWORD_TOO_SHORT'
  | 'PASSWORD_UNCHANGED'
  | 'INVALID_UPDATES_FORMAT'
  | 'EMPTY_UPDATES'
  | 'RESTRICTED_FIELD'
  | 'INVALID_PHONE_FORMAT'
  
  // URL and redirect errors
  | 'INVALID_AUTH_URL'
  | 'INVALID_LOGOUT_URL'
  
  // Generic operation errors
  | 'OPERATION_ERROR'
  | 'CALLBACK_ERROR'
  | 'LOGIN_INIT_ERROR'
  | 'RESET_REQUEST_ERROR'
  | 'PASSWORD_CHANGE_ERROR'
  | 'PROFILE_RETRIEVAL_ERROR'
  | 'DETAILED_PROFILE_RETRIEVAL_ERROR'
  | 'PROFILE_UPDATE_OPERATION_ERROR'
  | 'TOKEN_RETRIEVAL_ERROR'
  | 'TOKEN_REFRESH_FAILED'
  | 'LOGOUT_ERROR'
  | 'VERIFY_REQUEST_ERROR'
  | 'REFRESH_OPERATION_ERROR';

declare const gmfCiamAuth: GMFCIAMAuth;
export default gmfCiamAuth;
