import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

export interface JWTValidationResult {
  valid: boolean;
  payload?: JWTPayload;
  subject?: string;
  error?: string;
}

export class JWTValidator {
  private jwks: ReturnType<typeof createRemoteJWKSet>;
  private issuer: string;
  private audience?: string;

  constructor(issuer: string, jwksUri?: string, audience?: string) {
    this.issuer = issuer;
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

      return {
        valid: true,
        payload,
        subject: payload.sub
      };
    } catch (err) {
      return {
        valid: false,
        error: err instanceof Error ? err.message : 'Unknown validation error'
      };
    }
  }
}
