// Auth0 specific implementation
import { AuthProvider } from "../auth-provider.js";

export default class Auth0Provider extends AuthProvider {
  debugger;
  constructor(config) {
    console.log("[Auth0Provider] constructor called");
    super();
    if (!config || !config.domain || !config.clientId || !config.audience) {
      throw new Error("Missing required Auth0 configuration parameters");
    }

    this.config = {
      domain: config.domain,
      clientId: config.clientId,
      audience: config.audience,
      redirectUri: config.redirectUri || window.location.origin,
      scope: config.scope || "openid profile email offline_access",
      responseType: "code",
      cacheLocation: "localstorage",
      // Add management API configuration for advanced operations
      managementApiAudience: config.managementApiAudience || `https://${config.domain}/api/v2/`,
      // Add custom API endpoint configuration
      apiEndpoint: config.apiEndpoint || "/api", // Base API endpoint for custom calls
    };

    this.accessToken = null;
    this.refreshToken = null;
    this.managementToken = null; // Token for Management API calls
    this.userProfile = null;
    this.expiresAt = null;
    this.authenticated = false;

    // Initialize on creation
    this._initializeAuth();
  }

  _initializeAuth() {
    console.log("[Auth0Provider] _initializeAuth called");
    const storedAuth = localStorage.getItem("authClient");
    if (storedAuth) {
      try {
        const authData = JSON.parse(storedAuth);
        if (authData.expiresAt && new Date().getTime() < authData.expiresAt) {
          this.accessToken = authData.accessToken;
          this.refreshToken = authData.refreshToken;
          this.managementToken = authData.managementToken;
          this.userProfile = authData.userProfile;
          this.expiresAt = authData.expiresAt;
          this.authenticated = true;
        } else if (authData.refreshToken) {
          this._refreshToken(authData.refreshToken);
        } else {
          this._clearStorage();
        }
      } catch (e) {
        this._clearStorage();
      }
    }

    if (!this.authenticated && window.location.search.includes("code=")) {
      const isAuthenticated = this.authenticated;
      console.log("User is authenticated:", isAuthenticated);
      this._handleAuthCallback();
    }
  }

  _clearStorage() {
    console.log("[Auth0Provider] _clearStorage called");
    localStorage.removeItem("authClient");
    this.accessToken = null;
    this.refreshToken = null;
    this.managementToken = null;
    this.userProfile = null;
    this.expiresAt = null;
    this.authenticated = false;
  }

  async login() {
    console.log("[Auth0Provider] login called");
    try {
      const authUrl =
        `https://${this.config.domain}/authorize?` +
        `client_id=${this.config.clientId}&` +
        `redirect_uri=${encodeURIComponent(this.config.redirectUri)}&` +
        `response_type=${this.config.responseType}&` +
        `scope=${encodeURIComponent(this.config.scope)}&` +
        `audience=${encodeURIComponent(this.config.audience)}`;
      window.location.assign(authUrl);
    } catch (error) {
      console.error("Login failed:", error);
      throw error;
    }
  }

  async _handleAuthCallback() {
    console.log("[Auth0Provider] _handleAuthCallback called");
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get("code");

      if (!code) {
        throw new Error("No authorization code found in URL");
      }

      const tokenResponse = await fetch(
        `https://${this.config.domain}/oauth/token`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            grant_type: "authorization_code",
            client_id: this.config.clientId,
            code,
            redirect_uri: this.config.redirectUri,
          }),
        }
      );

      if (!tokenResponse.ok) {
        throw new Error("Failed to exchange code for token");
      }

      const tokenData = await tokenResponse.json();

      this.accessToken = tokenData.access_token;
      this.refreshToken = tokenData.refresh_token;
      this.expiresAt = new Date().getTime() + tokenData.expires_in * 1000;
      this.authenticated = true;

      // Get management token for advanced operations
      await this._getManagementToken();
      
      await this.getUserProfile();
      this._saveAuthData();

      const url = new URL(window.location.href);
      url.search = "";
      window.history.replaceState({}, document.title, url.toString());

      return true;
    } catch (error) {
      console.error("Authentication callback handling failed:", error);
      this._clearStorage();
      throw error;
    }
  }

  // NEW: Get Management API token for advanced operations
  async _getManagementToken() {
    console.log("[Auth0Provider] _getManagementToken called");
    try {
      const response = await fetch(`https://${this.config.domain}/oauth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client_id: this.config.clientId,
          client_secret: this.config.clientSecret, // Note: This should be handled server-side in production
          audience: this.config.managementApiAudience,
          grant_type: "client_credentials",
        }),
      });

      if (response.ok) {
        const tokenData = await response.json();
        this.managementToken = tokenData.access_token;
      } else {
        console.warn("Failed to get management token - some features may be limited");
      }
    } catch (error) {
      console.warn("Management token request failed:", error);
    }
  }

  async _refreshToken(refreshToken) {
    console.log("[Auth0Provider] _refreshToken called");
    try {
      const tokenResponse = await fetch(
        `https://${this.config.domain}/oauth/token`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            grant_type: "refresh_token",
            client_id: this.config.clientId,
            refresh_token: refreshToken,
          }),
        }
      );

      if (!tokenResponse.ok) {
        throw new Error("Failed to refresh access token");
      }

      const tokenData = await tokenResponse.json();
      
      this.accessToken = tokenData.access_token;
      this.refreshToken = tokenData.refresh_token || refreshToken;
      this.expiresAt = new Date().getTime() + tokenData.expires_in * 1000;
      this.authenticated = true;
      
      this._saveAuthData();
      
      return true;
    } catch (error) {
      console.error("Token refresh failed:", error);
      this._clearStorage();
      throw error;
    }
  }

  async refreshToken() {
    console.log("[Auth0Provider] refreshToken called");
    if (!this.refreshToken) {
      throw new Error("No refresh token available");
    }
    
    return this._refreshToken(this.refreshToken);
  }

  // UPDATED: Reset password using custom API endpoint
  async resetPassword(email) {
    console.log("[Auth0Provider] resetPassword called");
    if (!email) {
      throw new Error("Email is required for password reset");
    }
    
    try {
      const response = await fetch(`${this.config.apiEndpoint}/reset-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(this.accessToken && { "Authorization": `Bearer ${this.accessToken}` }),
        },
        body: JSON.stringify({
          email: email,
          password: null,
          firstname: "",
          lastname: "",
          usermetadata: {}
        }),
      });
      
      if (!response.ok) {
        let errorMessage = 'Unknown error occurred';
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorData.error || errorData.error_description || `HTTP ${response.status}: ${response.statusText}`;
        } catch (parseError) {
          errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        }
        throw new Error(`Password reset failed: ${errorMessage}`);
      }
      
      const result = await response.json();
      return result.message || "Password reset email sent successfully";
    } catch (error) {
      console.error("[Auth0Provider] Password reset request failed:", error);
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error("Network error: Unable to connect to the server. Please check your internet connection.");
      }
      throw error;
    }
  }

  // UPDATED: Change password using custom API endpoint
  async changePassword(oldPassword, newPassword) {
    console.log("[Auth0Provider] changePassword called");
    if (!this.authenticated || !this.userProfile) {
      throw new Error("User must be authenticated to change password");
    }

    if (!oldPassword || !newPassword) {
      throw new Error("Both old and new passwords are required");
    }

    if (newPassword.length < 8) {
      throw new Error("New password must be at least 8 characters long");
    }

    try {
      const response = await fetch(`${this.config.apiEndpoint}/change-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.accessToken}`,
        },
        body: JSON.stringify({
          email: this.userProfile.email,
          password: newPassword,
          oldPassword: oldPassword, // Include old password for verification
          firstname: this.userProfile.given_name || this.userProfile.name?.split(' ')[0] || "",
          lastname: this.userProfile.family_name || this.userProfile.name?.split(' ').slice(1).join(' ') || "",
          usermetadata: this.userProfile.user_metadata || {}
        }),
      });

      if (!response.ok) {
        let errorMessage = 'Unknown error occurred';
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorData.error || errorData.error_description || `HTTP ${response.status}: ${response.statusText}`;
        } catch (parseError) {
          errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        }
        throw new Error(`Password change failed: ${errorMessage}`);
      }

      const result = await response.json();
      return result.message || "Password changed successfully";
    } catch (error) {
      console.error("[Auth0Provider] Password change failed:", error);
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error("Network error: Unable to connect to the server. Please check your internet connection.");
      }
      if (error.message.includes('401') || error.message.includes('Unauthorized')) {
        throw new Error("Authentication failed: Please log in again.");
      }
      throw error;
    }
  }

  // ENHANCED: Get user profile with API fallback
  async getUserProfile(forceRefresh = false) {
    console.log("[Auth0Provider] getUserProfile called");
    if (!this.authenticated || !this.accessToken) {
      throw new Error("Not authenticated");
    }

    // Return cached profile unless force refresh is requested
    if (this.userProfile && !forceRefresh) {
      return this.userProfile;
    }

    try {
      const userInfoResponse = await fetch(
        `https://${this.config.domain}/userinfo`,
        {
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
          },
        }
      );

      if (!userInfoResponse.ok) {
        throw new Error("Failed to fetch user profile from userinfo endpoint");
      }

      this.userProfile = await userInfoResponse.json();
      this._saveAuthData();

      return this.userProfile;
    } catch (error) {
      console.error("Failed to get user profile:", error);
      throw error;
    }
  }

  // UPDATED: Get detailed user profile using custom API endpoint
  async getDetailedUserProfile() {
    console.log("[Auth0Provider] getDetailedUserProfile called");
    if (!this.authenticated || !this.userProfile) {
      throw new Error("User must be authenticated");
    }

    try {
      const response = await fetch(`${this.config.apiEndpoint}/user-profile`, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${this.accessToken}`,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        let errorMessage = 'Unknown error occurred';
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorData.error || errorData.error_description || `HTTP ${response.status}: ${response.statusText}`;
        } catch (parseError) {
          errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        }
        throw new Error(`Failed to get detailed profile: ${errorMessage}`);
      }

      const detailedProfile = await response.json();
      return detailedProfile;
    } catch (error) {
      console.error("[Auth0Provider] Failed to get detailed user profile:", error);
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error("Network error: Unable to connect to the server. Please check your internet connection.");
      }
      if (error.message.includes('401') || error.message.includes('Unauthorized')) {
        throw new Error("Authentication failed: Please log in again.");
      }
      if (error.message.includes('403') || error.message.includes('Forbidden')) {
        throw new Error("Access denied: You don't have permission to access this profile information.");
      }
      throw error;
    }
  }

  // UPDATED: Update user profile using custom API endpoint
  async updateUserProfile(updates) {
    console.log("[Auth0Provider] updateUserProfile called");
    if (!this.authenticated || !this.userProfile) {
      throw new Error("User must be authenticated");
    }

    if (!updates || typeof updates !== 'object') {
      throw new Error("Updates object is required");
    }

    try {
      // Prepare the request body in the required format
      const requestBody = {
        email: updates.email || this.userProfile.email,
        password: null, // Password is null for profile updates
        firstname: updates.firstname || updates.given_name || this.userProfile.given_name || "",
        lastname: updates.lastname || updates.family_name || this.userProfile.family_name || "",
        usermetadata: {
          ...this.userProfile.user_metadata,
          ...updates.usermetadata,
          ...updates.user_metadata
        }
      };

      const response = await fetch(`${this.config.apiEndpoint}/update-profile`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.accessToken}`,
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        let errorMessage = 'Unknown error occurred';
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorData.error || errorData.error_description || `HTTP ${response.status}: ${response.statusText}`;
        } catch (parseError) {
          errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        }
        throw new Error(`Profile update failed: ${errorMessage}`);
      }

      const updatedProfile = await response.json();
      
      // Refresh the cached profile
      try {
        await this.getUserProfile(true);
      } catch (refreshError) {
        console.warn("[Auth0Provider] Failed to refresh cached profile after update:", refreshError);
        // Continue execution even if cache refresh fails
      }
      
      return updatedProfile;
    } catch (error) {
      console.error("[Auth0Provider] Profile update failed:", error);
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error("Network error: Unable to connect to the server. Please check your internet connection.");
      }
      if (error.message.includes('401') || error.message.includes('Unauthorized')) {
        throw new Error("Authentication failed: Please log in again.");
      }
      if (error.message.includes('403') || error.message.includes('Forbidden')) {
        throw new Error("Access denied: You don't have permission to update this profile.");
      }
      if (error.message.includes('400') || error.message.includes('Bad Request')) {
        throw new Error("Invalid profile data: Please check the information you're trying to update.");
      }
      throw error;
    }
  }

  logout() {
    console.log("[Auth0Provider] logout called");
    this._clearStorage();

    const logoutUrl =
      `https://${this.config.domain}/v2/logout?` +
      `client_id=${this.config.clientId}&` +
      `returnTo=${encodeURIComponent(this.config.redirectUri)}`;

    window.location.assign(logoutUrl);
  }

  async isAuthenticated() {
    console.log("[Auth0Provider] isAuthenticated called");
    
    if (this.expiresAt && new Date().getTime() >= this.expiresAt && this.refreshToken) {
      try {
        await this.refreshToken();
      } catch (error) {
        return false;
      }
    }
    
    return (
      this.authenticated &&
      this.expiresAt &&
      new Date().getTime() < this.expiresAt
    );
  }

  async getAccessToken() {
    console.log("[Auth0Provider] getAccessToken called");
    
    if (this.expiresAt && new Date().getTime() >= this.expiresAt && this.refreshToken) {
      await this.refreshToken();
    }
    
    if (!this.isAuthenticated()) {
      throw new Error("Not authenticated");
    }
    
    return this.accessToken;
  }

  _saveAuthData() {
    console.log("[Auth0Provider] _saveAuthData called");
    localStorage.setItem(
      "authClient",
      JSON.stringify({
        accessToken: this.accessToken,
        refreshToken: this.refreshToken,
        managementToken: this.managementToken,
        userProfile: this.userProfile,
        expiresAt: this.expiresAt,
      })
    );
  }
}
