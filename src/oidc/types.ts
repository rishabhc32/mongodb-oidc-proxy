export interface OIDCProxyConfig {
  // OIDC Configuration
  issuer: string;
  clientId: string;
  jwksUri?: string;
  audience?: string;

  // Backend Configuration
  connectionString: string;

  // Proxy Configuration
  listenPort: number;
  listenHost?: string;

  // Limits
  maxConnections?: number; // Max concurrent connections (default: 10000)
  connectionTimeoutMs?: number; // Idle connection timeout in ms (default: 120000 = 2min)
}

export interface OIDCAuthState {
  conversationId: number;
  authenticated: boolean;
  principalName?: string;
  tokenExp?: number;
}

export interface IdpInfo {
  issuer: string;
  clientId: string;
  requestScopes?: string[];
}
