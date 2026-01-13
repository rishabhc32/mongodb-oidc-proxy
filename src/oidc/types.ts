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
}

export interface OIDCAuthState {
  conversationId: number;
  authenticated: boolean;
  principalName?: string;
}

export interface IdpInfo {
  issuer: string;
  clientId: string;
  requestScopes?: string[];
}

export interface SaslCommand {
  type: 'saslStart' | 'saslContinue';
  mechanism?: string;
  payload?: Buffer;
  conversationId?: number;
  db: string;
}
