import { createRemoteJWKSet, jwtVerify, errors, type JWTPayload } from 'jose';

export enum JWTValidationError {
  EXPIRED = 'expired',
  CLIENT_ID_MISMATCH = 'client_id_mismatch',
  INVALID = 'invalid'
}

export interface JWTValidationResult {
  valid: boolean;
  payload?: JWTPayload;
  subject?: string;
  exp?: number;
  errorCode?: JWTValidationError;
  error?: string;
}

export class JWTValidator {
  private jwks: ReturnType<typeof createRemoteJWKSet>;
  private issuer: string;
  private clientId: string;
  private audience?: string;

  constructor(issuer: string, clientId: string, jwksUri?: string, audience?: string) {
    this.issuer = issuer;
    this.clientId = clientId;
    this.audience = audience;

    // Default JWKS URI follows OpenID Connect Discovery spec
    const jwksUrl = jwksUri || `${issuer.replace(/\/$/, '')}/.well-known/jwks.json`;
    this.jwks = createRemoteJWKSet(new URL(jwksUrl));
  }

  async validate(token: string): Promise<JWTValidationResult> {
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        audience: this.audience
      });

      // Verify client_id
      const tokenClientId = (payload as Record<string, unknown>).client_id;
      if (!(typeof tokenClientId === 'string' && tokenClientId && tokenClientId === this.clientId)) {
        return {
          valid: false,
          errorCode: JWTValidationError.CLIENT_ID_MISMATCH,
          error: 'client_id mismatch'
        };
      }

      return {
        valid: true,
        payload,
        subject: payload.sub,
        exp: payload.exp
      };
    } catch (err) {
      return {
        valid: false,
        errorCode: err instanceof errors.JWTExpired ? JWTValidationError.EXPIRED : JWTValidationError.INVALID,
        error: err instanceof Error ? err.message : 'Unknown validation error'
      };
    }
  }
}
