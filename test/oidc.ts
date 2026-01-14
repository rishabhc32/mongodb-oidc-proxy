import assert from 'assert';
import { deserialize, serialize, Binary } from 'bson';
import net from 'net';
import { once } from 'events';
import { MessageBuilder, OIDCProxy, JWTValidator, JWTValidationError } from '../src/oidc';
import type { OIDCProxyConfig, JWTValidationResult } from '../src/oidc';

// Mock JWTValidator for testing authenticated flows
class MockJWTValidator extends JWTValidator {
  private mockResult: JWTValidationResult;

  constructor(result: JWTValidationResult) {
    super('https://mock.example.com', 'mock-client');
    this.mockResult = result;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async validate(_token: string): Promise<JWTValidationResult> {
    return this.mockResult;
  }
}

// Helper to build OP_MSG from a BSON document
function buildOpMsg(doc: Record<string, unknown>, requestId = 1): Buffer {
  const bsonDoc = Buffer.from(serialize(doc));
  const flagBits = Buffer.alloc(4);
  flagBits.writeUInt32LE(0, 0);
  const sectionKind = Buffer.alloc(1);
  sectionKind.writeUInt8(0, 0);

  const bodyLength = 4 + 1 + bsonDoc.length;
  const messageLength = 16 + bodyLength;

  const header = Buffer.alloc(16);
  header.writeInt32LE(messageLength, 0);
  header.writeInt32LE(requestId, 4);
  header.writeInt32LE(0, 8);
  header.writeInt32LE(2013, 12); // OP_MSG

  return Buffer.concat([header, flagBits, sectionKind, bsonDoc]);
}

// Helper class to read multiple responses from a socket
class ResponseReader {
  private buffer = Buffer.alloc(0);
  private resolvers: Array<(data: Buffer) => void> = [];

  constructor(client: net.Socket) {
    client.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.processBuffer();
    });
  }

  private processBuffer(): void {
    while (this.buffer.length >= 4 && this.resolvers.length > 0) {
      const expectedLen = this.buffer.readInt32LE(0);
      if (this.buffer.length >= expectedLen) {
        const response = this.buffer.subarray(0, expectedLen);
        this.buffer = this.buffer.subarray(expectedLen);
        const resolve = this.resolvers.shift();
        if (resolve) resolve(Buffer.from(response));
      } else {
        break;
      }
    }
  }

  read(): Promise<Buffer> {
    return new Promise((resolve) => {
      this.resolvers.push(resolve);
      this.processBuffer();
    });
  }
}

// Helper to wait for a complete MongoDB response (single use)
function waitForResponse(client: net.Socket): Promise<Buffer> {
  return new ResponseReader(client).read();
}

describe('MessageBuilder', function() {
  let builder: MessageBuilder;

  beforeEach(() => {
    builder = new MessageBuilder();
  });

  describe('buildOpMsg', () => {
    it('creates valid OP_MSG structure', () => {
      const doc = { ok: 1, test: 'value' };
      const msg = builder.buildOpMsg(123, doc);

      // Parse header
      const messageLength = msg.readInt32LE(0);
      const responseTo = msg.readInt32LE(8);
      const opCode = msg.readInt32LE(12);

      assert.strictEqual(messageLength, msg.length);
      assert.strictEqual(responseTo, 123);
      assert.strictEqual(opCode, 2013); // OP_MSG

      // Parse body
      const flagBits = msg.readUInt32LE(16);
      const sectionKind = msg.readUInt8(20);

      assert.strictEqual(flagBits, 0);
      assert.strictEqual(sectionKind, 0); // Body section

      // Parse BSON document
      const bsonData = msg.subarray(21);
      const parsed = deserialize(bsonData);
      assert.strictEqual(parsed.ok, 1);
      assert.strictEqual(parsed.test, 'value');
    });
  });

  describe('buildSaslStartResponse', () => {
    it('creates response with IdP info in payload', () => {
      const idpInfo = { issuer: 'https://example.com', clientId: 'test-client' };
      const msg = builder.buildSaslStartResponse(456, 1, idpInfo);

      // Parse to get the response document
      const bsonData = msg.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.conversationId, 1);
      assert.strictEqual(parsed.done, false);
      assert.strictEqual(parsed.ok, 1);
      assert(parsed.payload instanceof Binary);

      // Parse the payload BSON
      const payloadDoc = deserialize(parsed.payload.buffer);
      assert.strictEqual(payloadDoc.issuer, 'https://example.com');
      assert.strictEqual(payloadDoc.clientId, 'test-client');
    });

    it('includes requestScopes when provided', () => {
      const idpInfo = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        requestScopes: ['openid', 'profile']
      };
      const msg = builder.buildSaslStartResponse(456, 1, idpInfo);

      const bsonData = msg.subarray(21);
      const parsed = deserialize(bsonData);
      const payloadDoc = deserialize(parsed.payload.buffer);

      assert.deepStrictEqual(payloadDoc.requestScopes, ['openid', 'profile']);
    });
  });

  describe('buildAuthSuccessResponse', () => {
    it('creates response with done=true', () => {
      const msg = builder.buildAuthSuccessResponse(789, 5);

      const bsonData = msg.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.conversationId, 5);
      assert.strictEqual(parsed.done, true);
      assert.strictEqual(parsed.ok, 1);
    });
  });

  describe('buildAuthFailureResponse', () => {
    it('creates error response with default code 18', () => {
      const msg = builder.buildAuthFailureResponse(100, 'Auth failed');

      const bsonData = msg.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 0);
      assert.strictEqual(parsed.errmsg, 'Auth failed');
      assert.strictEqual(parsed.code, 18);
      assert.strictEqual(parsed.codeName, 'AuthenticationFailed');
    });

    it('uses custom error code', () => {
      const msg = builder.buildAuthFailureResponse(100, 'Custom error', 42);

      const bsonData = msg.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.code, 42);
      assert.strictEqual(parsed.codeName, 'UnknownError');
    });
  });

  describe('buildErrorResponse', () => {
    it('creates error response with custom code and codeName', () => {
      const msg = builder.buildErrorResponse(200, 'Something went wrong', 391, 'ReauthenticationRequired');

      const bsonData = msg.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 0);
      assert.strictEqual(parsed.errmsg, 'Something went wrong');
      assert.strictEqual(parsed.code, 391);
      assert.strictEqual(parsed.codeName, 'ReauthenticationRequired');
    });
  });

  describe('buildOpReply', () => {
    it('creates valid OP_REPLY structure', () => {
      const doc = { ismaster: true, ok: 1 };
      const msg = builder.buildOpReply(300, doc);

      // Parse header
      const messageLength = msg.readInt32LE(0);
      const responseTo = msg.readInt32LE(8);
      const opCode = msg.readInt32LE(12);

      assert.strictEqual(messageLength, msg.length);
      assert.strictEqual(responseTo, 300);
      assert.strictEqual(opCode, 1); // OP_REPLY

      // Parse OP_REPLY body
      const responseFlags = msg.readInt32LE(16);
      const cursorId = msg.readBigInt64LE(20);
      const startingFrom = msg.readInt32LE(28);
      const numberReturned = msg.readInt32LE(32);

      assert.strictEqual(responseFlags, 0);
      assert.strictEqual(cursorId, BigInt(0));
      assert.strictEqual(startingFrom, 0);
      assert.strictEqual(numberReturned, 1);

      // Parse BSON document
      const bsonData = msg.subarray(36);
      const parsed = deserialize(bsonData);
      assert.strictEqual(parsed.ismaster, true);
      assert.strictEqual(parsed.ok, 1);
    });
  });

  describe('buildCommandResponse', () => {
    it('adds ok:1 if not present', () => {
      const msg = builder.buildCommandResponse(400, { result: 'test' });

      const bsonData = msg.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 1);
      assert.strictEqual(parsed.result, 'test');
    });

    it('preserves existing ok value', () => {
      const msg = builder.buildCommandResponse(400, { ok: 0, errmsg: 'error' });

      const bsonData = msg.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 0);
    });
  });
});

describe('OIDCProxy', function() {
  let hostport: string;

  before(() => {
    if (!process.env.MONGODB_HOSTPORT) {
      throw new Error('MONGODB_HOSTPORT not set');
    }
    hostport = process.env.MONGODB_HOSTPORT;
  });

  describe('connection handling', () => {
    it('emits newConnection event on client connect', async() => {
      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;
      const connectionPromise = once(proxy, 'newConnection');

      const client = new net.Socket();
      client.connect(addr.port, 'localhost');

      const [connInfo] = await connectionPromise;
      assert(connInfo.id > 0);
      assert(typeof connInfo.incoming === 'string');

      client.destroy();
      await proxy.stop();
    });

    it('emits connectionClosed event on client disconnect', async() => {
      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      const client = new net.Socket();
      client.connect(addr.port, 'localhost');
      await once(proxy, 'newConnection');

      const closePromise = once(proxy, 'connectionClosed');
      client.destroy();

      const [connId] = await closePromise;
      assert(typeof connId === 'number');

      await proxy.stop();
    });

    it('respects maxConnections limit', async() => {
      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0,
        maxConnections: 2
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      // Connect 2 clients (at the limit)
      const client1 = new net.Socket();
      const client2 = new net.Socket();
      client1.connect(addr.port, 'localhost');
      client2.connect(addr.port, 'localhost');
      await once(proxy, 'newConnection');
      await once(proxy, 'newConnection');

      // Third connection should be rejected
      const client3 = new net.Socket();
      const closePromise = once(client3, 'close');
      client3.connect(addr.port, 'localhost');
      await closePromise;

      client1.destroy();
      client2.destroy();
      await proxy.stop();
    });

    it('emits connectionTimeout on idle connections', async() => {
      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0,
        connectionTimeoutMs: 50 // Very short timeout for testing
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      const client = new net.Socket();
      client.connect(addr.port, 'localhost');
      await once(proxy, 'newConnection');

      const [connId] = await once(proxy, 'connectionTimeout');
      assert(typeof connId === 'number');

      await proxy.stop();
    });
  });

  describe('hello/ismaster handling', () => {
    it('responds to hello command with OIDC mechanism', async() => {
      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      const msg = buildOpMsg({ hello: 1, $db: 'admin' });

      const client = new net.Socket();
      const responsePromise = waitForResponse(client);

      client.connect(addr.port, 'localhost', () => {
        client.write(msg);
      });

      const response = await responsePromise;

      // Parse response
      const bsonData = response.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ismaster, true);
      assert.strictEqual(parsed.ok, 1);
      assert.deepStrictEqual(parsed.saslSupportedMechs, ['MONGODB-OIDC']);

      client.destroy();
      await proxy.stop();
    });
  });

  describe('SASL authentication flow', () => {
    it('returns IdP info on saslStart without JWT', async() => {
      const config: OIDCProxyConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'my-client-id',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      const msg = buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({}))),
        $db: 'admin'
      });

      const client = new net.Socket();
      const responsePromise = waitForResponse(client);

      client.connect(addr.port, 'localhost', () => {
        client.write(msg);
      });

      const response = await responsePromise;
      const bsonData = response.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 1);
      assert.strictEqual(parsed.done, false);
      assert(typeof parsed.conversationId === 'number');
      assert(parsed.payload instanceof Binary);

      // Parse IdP info from payload
      const idpInfo = deserialize(parsed.payload.buffer);
      assert.strictEqual(idpInfo.issuer, 'https://auth.example.com');
      assert.strictEqual(idpInfo.clientId, 'my-client-id');

      client.destroy();
      await proxy.stop();
    });

    it('rejects commands without authentication', async() => {
      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      const msg = buildOpMsg({ find: 'test', $db: 'test' });

      const client = new net.Socket();
      const authRequiredPromise = once(proxy, 'authRequired');
      const responsePromise = waitForResponse(client);

      client.connect(addr.port, 'localhost', () => {
        client.write(msg);
      });

      const [connId, cmdName] = await authRequiredPromise;
      assert(typeof connId === 'number');
      assert.strictEqual(cmdName, 'find');

      const response = await responsePromise;
      const bsonData = response.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 0);
      assert.strictEqual(parsed.code, 13);
      assert(parsed.errmsg.includes('Authentication required'));

      client.destroy();
      await proxy.stop();
    });

    it('allows ping without authentication', async() => {
      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      const msg = buildOpMsg({ ping: 1, $db: 'admin' });

      const client = new net.Socket();
      const responsePromise = waitForResponse(client);

      client.connect(addr.port, 'localhost', () => {
        client.write(msg);
      });

      const response = await responsePromise;
      const bsonData = response.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 1);

      client.destroy();
      await proxy.stop();
    });
  });

  describe('saslContinue handling', () => {
    it('rejects saslContinue with invalid conversationId', async() => {
      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      // Send saslContinue without prior saslStart (conversationId won't match)
      const msg = buildOpMsg({
        saslContinue: 1,
        conversationId: 999, // Invalid - no saslStart was done
        payload: new Binary(Buffer.from(serialize({ jwt: 'fake.jwt.token' }))),
        $db: 'admin'
      });

      const client = new net.Socket();
      const responsePromise = waitForResponse(client);

      client.connect(addr.port, 'localhost', () => {
        client.write(msg);
      });

      const response = await responsePromise;
      const bsonData = response.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 0);
      assert(parsed.errmsg.includes('Invalid conversationId'));

      client.destroy();
      await proxy.stop();
    });
  });
});

describe('JWTValidator', function() {
  it('constructs with default JWKS URI', () => {
    // Just verify it doesn't throw
    const validator = new JWTValidator('https://auth.example.com', 'client-id');
    assert(validator !== null);
  });

  it('constructs with custom JWKS URI', () => {
    const validator = new JWTValidator(
      'https://auth.example.com',
      'client-id',
      'https://auth.example.com/custom/jwks'
    );
    assert(validator !== null);
  });

  it('constructs with audience', () => {
    const validator = new JWTValidator(
      'https://auth.example.com',
      'client-id',
      undefined,
      'https://api.example.com'
    );
    assert(validator !== null);
  });
});

describe('OIDCProxy with mock validator', function() {
  let hostport: string;

  before(() => {
    if (!process.env.MONGODB_HOSTPORT) {
      throw new Error('MONGODB_HOSTPORT not set');
    }
    hostport = process.env.MONGODB_HOSTPORT;
  });

  describe('successful authentication via saslStart', () => {
    it('authenticates when JWT is valid in saslStart payload', async() => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
      });

      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config, mockValidator);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;
      const authSuccessPromise = once(proxy, 'authSuccess');

      // Send saslStart with a JWT in payload
      const msg = buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({ jwt: 'mock.jwt.token' }))),
        $db: 'admin'
      });

      const client = new net.Socket();
      const responsePromise = waitForResponse(client);

      client.connect(addr.port, 'localhost', () => {
        client.write(msg);
      });

      const [connId, subject] = await authSuccessPromise;
      assert(typeof connId === 'number');
      assert(subject.includes('test-user@example.com'));

      const response = await responsePromise;
      const bsonData = response.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 1);
      assert.strictEqual(parsed.done, true); // Auth complete

      client.destroy();
      await proxy.stop();
    });
  });

  describe('saslStart without JWT', () => {
    it('returns IdP info when no JWT in payload', async() => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        exp: Math.floor(Date.now() / 1000) + 3600
      });

      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config, mockValidator);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      const client = new net.Socket();
      const responsePromise = waitForResponse(client);

      client.connect(addr.port, 'localhost', () => {
        const msg = buildOpMsg({
          saslStart: 1,
          mechanism: 'MONGODB-OIDC',
          payload: new Binary(Buffer.from(serialize({}))),
          $db: 'admin'
        });
        client.write(msg);
      });

      const response = await responsePromise;
      const parsed = deserialize(response.subarray(21));

      assert.strictEqual(parsed.ok, 1);
      assert.strictEqual(parsed.done, false);
      assert(typeof parsed.conversationId === 'number');

      client.destroy();
      await proxy.stop();
    });
  });

  describe('command forwarding after auth', () => {
    it('emits commandForwarded event on successful forward', async() => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        exp: Math.floor(Date.now() / 1000) + 3600
      });

      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config, mockValidator);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;
      const commandForwardedPromise = once(proxy, 'commandForwarded');

      const client = new net.Socket();
      const reader = new ResponseReader(client);
      await new Promise<void>((resolve) => client.connect(addr.port, 'localhost', resolve));

      // Authenticate
      const saslStartMsg = buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({ jwt: 'mock.jwt.token' }))),
        $db: 'admin'
      }, 1);

      client.write(saslStartMsg);
      await reader.read(); // Wait for auth response

      // Send a find command (requestId 2)
      const findMsg = buildOpMsg({ find: 'test', $db: 'test' }, 2);
      client.write(findMsg);

      const [connId, dbName, cmdName] = await commandForwardedPromise;
      assert(typeof connId === 'number');
      assert.strictEqual(dbName, 'test');
      assert.strictEqual(cmdName, 'find');

      client.destroy();
      await proxy.stop();
    });
  });

  describe('token expiration handling', () => {
    it('returns reauth error when token is expired', async() => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        exp: Math.floor(Date.now() / 1000) - 10 // Already expired
      });

      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config, mockValidator);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;
      const reauthPromise = once(proxy, 'reauthRequired');

      const client = new net.Socket();
      const reader = new ResponseReader(client);
      await new Promise<void>((resolve) => client.connect(addr.port, 'localhost', resolve));

      // Authenticate (will succeed but token is expired)
      const saslStartMsg = buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({ jwt: 'mock.jwt.token' }))),
        $db: 'admin'
      }, 1);

      client.write(saslStartMsg);
      await reader.read(); // Wait for auth response

      // Send a command - should trigger reauth
      const findMsg = buildOpMsg({ find: 'test', $db: 'test' }, 2);
      client.write(findMsg);

      const [connId, reason] = await reauthPromise;
      assert(typeof connId === 'number');
      assert(reason.includes('expired'));

      client.destroy();
      await proxy.stop();
    });

    it('returns reauth error when saslStart JWT is expired', async() => {
      const mockValidator = new MockJWTValidator({
        valid: false,
        errorCode: JWTValidationError.EXPIRED,
        error: 'Token expired'
      });

      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config, mockValidator);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      const client = new net.Socket();
      const responsePromise = waitForResponse(client);

      client.connect(addr.port, 'localhost', () => {
        const msg = buildOpMsg({
          saslStart: 1,
          mechanism: 'MONGODB-OIDC',
          payload: new Binary(Buffer.from(serialize({ jwt: 'expired.jwt.token' }))),
          $db: 'admin'
        });
        client.write(msg);
      });

      const response = await responsePromise;
      const bsonData = response.subarray(21);
      const parsed = deserialize(bsonData);

      assert.strictEqual(parsed.ok, 0);
      assert.strictEqual(parsed.code, 391); // ReauthenticationRequired
      assert(parsed.errmsg.includes('Reauthentication required'));

      client.destroy();
      await proxy.stop();
    });
  });

  describe('auth failure handling', () => {
    it('returns error when JWT is invalid in saslStart', async() => {
      const mockValidator = new MockJWTValidator({
        valid: false,
        errorCode: JWTValidationError.INVALID,
        error: 'Invalid signature'
      });

      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0
      };

      const proxy = new OIDCProxy(config, mockValidator);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      // When JWT is invalid in saslStart, it falls back to returning IdP info
      // (so client can get a new token)
      const client = new net.Socket();
      const responsePromise = waitForResponse(client);

      client.connect(addr.port, 'localhost', () => {
        const msg = buildOpMsg({
          saslStart: 1,
          mechanism: 'MONGODB-OIDC',
          payload: new Binary(Buffer.from(serialize({ jwt: 'invalid.jwt.token' }))),
          $db: 'admin'
        });
        client.write(msg);
      });

      const response = await responsePromise;
      const parsed = deserialize(response.subarray(21));

      // Since JWT was invalid (not expired), it returns IdP info for retry
      assert.strictEqual(parsed.ok, 1);
      assert.strictEqual(parsed.done, false);

      client.destroy();
      await proxy.stop();
    });
  });
});
