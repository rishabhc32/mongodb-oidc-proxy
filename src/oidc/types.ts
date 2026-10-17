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
  maxConnectionsPerUser?: number; // Max concurrent authenticated connections per user (default: unlimited)
  connectionTimeoutMs?: number; // Idle connection timeout in ms (default: 120000 = 2min)
}

export interface IdpInfo {
  issuer: string;
  clientId: string;
  requestScopes?: string[];
}
