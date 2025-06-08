// src/types/index.d.ts
export interface AuthConfig {
  domain: string;
  clientId: string;
  audience?: string;
  redirectUri?: string;
  scope?: string;
  responseType?: string;
  cacheLocation?: string;
  apiEndpoint?: string; // NEW: Custom API endpoint for profile operations
}

export interface OktaConfig {
  orgUrl: string;
  clientId: string;
  redirectUri?: string;
  scopes?: string[];
  apiEndpoint?: string; // NEW: Custom API endpoint for profile operations
}

export interface UserProfile {
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
  user_metadata?: any;
  [key: string]: any;
}

// NEW: Interface for profile update requests
export interface ProfileUpdateRequest {
  email?: string;
  firstname?: string;
  lastname?: string;
  usermetadata?: any;
}

export interface AuthProvider {
  login(): Promise<void>;
  logout(): void;
  getUserProfile(forceRefresh?: boolean): Promise<UserProfile>;
  isAuthenticated(): boolean | Promise<boolean>;
  getAccessToken(): string | Promise<string>;
  refreshToken(): Promise<boolean>;
  resetPassword(email: string): Promise<string>;
  changePassword(oldPassword: string, newPassword: string): Promise<string>;
  getDetailedUserProfile(): Promise<UserProfile>;
  updateUserProfile(updates: ProfileUpdateRequest): Promise<UserProfile>;
}

export interface GMFCIAMAuth {
  createAuthProvider(type: 'auth0' | 'okta', config: AuthConfig | OktaConfig): Promise<AuthProvider>;
}

declare const gmfCiamAuth: GMFCIAMAuth;
export default gmfCiamAuth;
