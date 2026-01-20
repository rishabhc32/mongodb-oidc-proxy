import assert from 'assert';
import { deserialize, serialize, Binary } from 'bson';
import net from 'net';
import http from 'http';
import { once } from 'events';
import { MongoClient } from 'mongodb';
import { MessageBuilder, OIDCProxy, JWTValidator, JWTValidationError } from '@src/oidc';
import type { OIDCProxyConfig, JWTValidationResult } from '@src/oidc';
import * as random from '@src/utils/random';
import sinon from 'sinon';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';

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
    it('emits newConnection event on client connect', async () => {
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
      assert(typeof connInfo.connId === 'string' && connInfo.connId.length > 0);
      assert(typeof connInfo.incoming === 'string');

      client.destroy();
      await proxy.stop();
    });

    it('emits connectionClosed event on client disconnect', async () => {
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
      const [conn] = await once(proxy, 'newConnection');

      const closePromise = once(conn, 'connectionClosed');
      client.destroy();

      await closePromise;
      assert(typeof conn.connId === 'string' && conn.connId.length > 0);

      await proxy.stop();
    });

    it('respects maxConnections limit', async () => {
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

    it('emits connectionTimeout on idle connections', async () => {
      const config: OIDCProxyConfig = {
        issuer: 'https://example.com',
        clientId: 'test-client',
        connectionString: `mongodb://${hostport}`,
        listenPort: 0,
        connectionTimeoutMs: 10 // Very short timeout for testing
      };

      const proxy = new OIDCProxy(config);
      await proxy.start();

      const addr = proxy.address() as net.AddressInfo;

      const client = new net.Socket();
      client.connect(addr.port, 'localhost');
      const [conn] = await once(proxy, 'newConnection');

      await once(conn, 'connectionTimeout');
      assert(typeof conn.connId === 'string' && conn.connId.length > 0);

      await proxy.stop();
    });
  });

  describe('provisioning cache and singleflight', () => {
    const email = 'cache-test@example.com';
    let adminClient: MongoClient;

    before(async () => {
      adminClient = new MongoClient(`mongodb://${hostport}`);
      await adminClient.connect();
      await adminClient.db('admin').command({
        createRole: email,
        privileges: [],
        roles: []
      });
    });

    after(async () => {
      const adminDb = adminClient.db('admin');
      await adminDb.command({ dropUser: email }).catch(() => { });
      await adminDb.command({ dropRole: email }).catch(() => { });
      await adminClient.close();
    });

    it('reuses cached password for repeated provisions', async () => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: email,
        email: email,
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

      // First auth - creates user with new password
      const client1 = new net.Socket();
      const reader1 = new ResponseReader(client1);
      await new Promise<void>((resolve) => client1.connect(addr.port, 'localhost', resolve));

      client1.write(buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({ jwt: 'mock.jwt.token' }))),
        $db: 'admin'
      }));
      await reader1.read();
      const firstPassword = (proxy as any).userPasswordCache.get(email);
      client1.destroy();

      // Second auth - should reuse cached password
      const client2 = new net.Socket();
      const reader2 = new ResponseReader(client2);
      await new Promise<void>((resolve) => client2.connect(addr.port, 'localhost', resolve));

      client2.write(buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({ jwt: 'mock.jwt.token' }))),
        $db: 'admin'
      }));
      await reader2.read();
      const secondPassword = (proxy as any).userPasswordCache.get(email);
      client2.destroy();

      assert.strictEqual(firstPassword, secondPassword);

      await proxy.stop();
    });

    it('deduplicates concurrent provisions via singleflight', async () => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: email,
        email: email,
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
      (proxy as any).userPasswordCache.clear();

      const addr = proxy.address() as net.AddressInfo;

      let calls = 0;
      const stub = sinon.stub(random, 'randomBytes').callsFake((size: number) => {
        calls += 1;
        return Buffer.alloc(size);
      });

      try {
        // Connect two clients simultaneously
        const client1 = new net.Socket();
        const client2 = new net.Socket();
        const reader1 = new ResponseReader(client1);
        const reader2 = new ResponseReader(client2);

        await Promise.all([
          new Promise<void>((resolve) => client1.connect(addr.port, 'localhost', resolve)),
          new Promise<void>((resolve) => client2.connect(addr.port, 'localhost', resolve))
        ]);

        // Send auth requests concurrently
        const authMsg = buildOpMsg({
          saslStart: 1,
          mechanism: 'MONGODB-OIDC',
          payload: new Binary(Buffer.from(serialize({ jwt: 'mock.jwt.token' }))),
          $db: 'admin'
        });

        client1.write(authMsg);
        client2.write(authMsg);

        await Promise.all([reader1.read(), reader2.read()]);

        client1.destroy();
        client2.destroy();

        // Singleflight should deduplicate - only one password generation
        assert.strictEqual(calls, 1);
      } finally {
        stub.restore();
        await proxy.stop();
      }
    });
  });

  describe('hello handling and command error logging', () => {
    before(async () => {
      const adminClient = new MongoClient(`mongodb://${hostport}`);
      await adminClient.connect();
      try {
        await adminClient.db('admin').command({
          createRole: 'test-user@example.com',
          privileges: [],
          roles: []
        });
      } catch (err: any) {
        if (err.code !== 11000 && !err.message.includes('already exists')) {
          throw err;
        }
      } finally {
        await adminClient.close();
      }
    });

    it('responds to hello command with OIDC mechanism', async () => {
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

    it('emits commandError with db/cmd on failing command', async () => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        email: 'test-user@example.com',
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
      const reader = new ResponseReader(client);
      await new Promise<void>((resolve) => client.connect(addr.port, 'localhost', resolve));

      const [conn] = await once(proxy, 'newConnection');
      const commandErrorPromise = once(conn, 'commandError');
      const authSuccessPromise = once(conn, 'authSuccess');

      // Authenticate
      const saslStartMsg = buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({ jwt: 'mock.jwt.token' }))),
        $db: 'admin'
      }, 1);

      client.write(saslStartMsg);
      await reader.read(); // Wait for auth response
      await authSuccessPromise;

      // Send an invalid command (requestId 2)
      const invalidCmd = buildOpMsg({ doesNotExist: 1, $db: 'admin' }, 2);
      client.write(invalidCmd);

      const [user, error, dbName, cmdName, request] = await commandErrorPromise;
      assert.strictEqual(user, 'test-user@example.com');
      assert.strictEqual(dbName, 'admin');
      assert.strictEqual(cmdName, 'doesNotExist');
      assert.strictEqual(typeof error, 'string');
      assert(error.length > 0);
      assert.deepStrictEqual(request?.doesNotExist, 1);

      client.destroy();
      await proxy.stop();
    });
  });

  describe('SASL authentication flow', () => {
    it('returns IdP info on saslStart without JWT', async () => {
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

    it('emits saslStart event when returning IdP info', async () => {
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
      const connectionPromise = once(proxy, 'newConnection');

      client.connect(addr.port, 'localhost');
      const [conn] = await connectionPromise;

      const saslStartPromise = once(conn, 'saslStart');

      const msg = buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({}))),
        $db: 'admin'
      });
      client.write(msg);

      const [idpInfo] = await saslStartPromise;
      assert.strictEqual(idpInfo.issuer, 'https://example.com');
      assert.strictEqual(idpInfo.clientId, 'test-client');

      client.destroy();
      await proxy.stop();
    });

    it('emits authAttempt event when JWT is provided', async () => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        email: 'test-user@example.com',
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
      const connectionPromise = once(proxy, 'newConnection');

      client.connect(addr.port, 'localhost');
      const [conn] = await connectionPromise;

      const authAttemptPromise = once(conn, 'authAttempt');

      const msg = buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({ jwt: 'mock.jwt.token' }))),
        $db: 'admin'
      });
      client.write(msg);

      const [user, jwt] = await authAttemptPromise;
      // user can be undefined, null, or string (email from decoded JWT)
      assert(user === undefined || user === null || typeof user === 'string');
      // jwt can be null or object (decoded JWT payload)
      assert(jwt === null || typeof jwt === 'object');

      client.destroy();
      await proxy.stop();
    });

    it('rejects commands without authentication', async () => {
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
      const connectionPromise = once(proxy, 'newConnection');

      client.connect(addr.port, 'localhost');
      const [conn] = await connectionPromise;

      const authRequiredPromise = once(conn, 'authRequired');
      const responsePromise = waitForResponse(client);

      client.write(msg);

      const [cmdName] = await authRequiredPromise;
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

    it('allows ping without authentication', async () => {
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
    it('rejects saslContinue with invalid conversationId', async () => {
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

  it('returns INVALID error for malformed token', async () => {
    const validator = new JWTValidator('https://auth.example.com', 'client-id');
    const result = await validator.validate('not-a-valid-jwt');
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.errorCode, JWTValidationError.INVALID);
    assert(result.error !== undefined);
  });

  it('returns INVALID error for empty token', async () => {
    const validator = new JWTValidator('https://auth.example.com', 'client-id');
    const result = await validator.validate('');
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.errorCode, JWTValidationError.INVALID);
  });

  it('returns INVALID error for JWT with invalid structure', async () => {
    const validator = new JWTValidator('https://auth.example.com', 'client-id');
    // JWT-like format but invalid
    const result = await validator.validate('header.payload.signature');
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.errorCode, JWTValidationError.INVALID);
  });
});

describe('JWTValidator with real keys', function() {
  this.timeout(10_000);

  let jwksServer: http.Server;
  let jwksPort: number;
  let privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
  let publicJwk: Awaited<ReturnType<typeof exportJWK>>;

  before(async () => {
    // Generate RSA key pair for signing JWTs
    const keyPair = await generateKeyPair('RS256');
    privateKey = keyPair.privateKey;
    publicJwk = await exportJWK(keyPair.publicKey);
    publicJwk.kid = 'test-key-id';
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig';

    // Create a mock JWKS server
    jwksServer = http.createServer((req, res) => {
      if (req.url === '/.well-known/jwks.json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ keys: [publicJwk] }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    jwksServer.listen(0);
    await once(jwksServer, 'listening');
    jwksPort = (jwksServer.address() as net.AddressInfo).port;
  });

  after(async () => {
    jwksServer.close();
    await once(jwksServer, 'close');
  });

  async function createSignedJWT(claims: Record<string, unknown>): Promise<string> {
    return new SignJWT(claims as any)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-id' })
      .setIssuer(`http://localhost:${jwksPort}`)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);
  }

  it('validates JWT successfully with all required claims', async () => {
    const validator = new JWTValidator(
      `http://localhost:${jwksPort}`,
      'test-client-id'
    );

    const token = await createSignedJWT({
      client_id: 'test-client-id',
      email: 'user@example.com',
      sub: 'user-123'
    });

    const result = await validator.validate(token);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.email, 'user@example.com');
    assert.strictEqual(result.subject, 'user-123');
    assert(result.exp !== undefined);
  });

  it('returns CLIENT_ID_MISMATCH when client_id does not match', async () => {
    const validator = new JWTValidator(
      `http://localhost:${jwksPort}`,
      'expected-client-id'
    );

    const token = await createSignedJWT({
      client_id: 'wrong-client-id',
      email: 'user@example.com'
    });

    const result = await validator.validate(token);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.errorCode, JWTValidationError.CLIENT_ID_MISMATCH);
    assert.strictEqual(result.error, 'client_id mismatch');
  });

  it('returns INVALID when email claim is missing', async () => {
    const validator = new JWTValidator(
      `http://localhost:${jwksPort}`,
      'test-client-id'
    );

    const token = await createSignedJWT({
      client_id: 'test-client-id',
      sub: 'user-123'
      // no email
    });

    const result = await validator.validate(token);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.errorCode, JWTValidationError.INVALID);
    assert.strictEqual(result.error, 'Email claim is required in JWT');
  });

  it('returns INVALID when client_id is missing', async () => {
    const validator = new JWTValidator(
      `http://localhost:${jwksPort}`,
      'test-client-id'
    );

    const token = await createSignedJWT({
      email: 'user@example.com'
      // no client_id
    });

    const result = await validator.validate(token);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.errorCode, JWTValidationError.CLIENT_ID_MISMATCH);
  });

  it('returns EXPIRED for expired token', async () => {
    const validator = new JWTValidator(
      `http://localhost:${jwksPort}`,
      'test-client-id'
    );

    // Create an already-expired token
    const token = await new SignJWT({
      client_id: 'test-client-id',
      email: 'user@example.com'
    } as any)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-id' })
      .setIssuer(`http://localhost:${jwksPort}`)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200) // 2 hours ago
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600) // 1 hour ago
      .sign(privateKey);

    const result = await validator.validate(token);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.errorCode, JWTValidationError.EXPIRED);
  });

  it('validates with custom JWKS URI', async () => {
    const validator = new JWTValidator(
      `http://localhost:${jwksPort}`,
      'test-client-id',
      `http://localhost:${jwksPort}/.well-known/jwks.json`
    );

    const token = await createSignedJWT({
      client_id: 'test-client-id',
      email: 'user@example.com'
    });

    const result = await validator.validate(token);
    assert.strictEqual(result.valid, true);
  });

  it('validates with audience check', async () => {
    const validator = new JWTValidator(
      `http://localhost:${jwksPort}`,
      'test-client-id',
      undefined,
      'https://api.example.com'
    );

    const token = await new SignJWT({
      client_id: 'test-client-id',
      email: 'user@example.com'
    } as any)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-id' })
      .setIssuer(`http://localhost:${jwksPort}`)
      .setAudience('https://api.example.com')
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);

    const result = await validator.validate(token);
    assert.strictEqual(result.valid, true);
  });

  it('returns INVALID when audience does not match', async () => {
    const validator = new JWTValidator(
      `http://localhost:${jwksPort}`,
      'test-client-id',
      undefined,
      'https://api.example.com'
    );

    const token = await new SignJWT({
      client_id: 'test-client-id',
      email: 'user@example.com'
    } as any)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-id' })
      .setIssuer(`http://localhost:${jwksPort}`)
      .setAudience('https://wrong-audience.com')
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);

    const result = await validator.validate(token);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.errorCode, JWTValidationError.INVALID);
  });
});

describe('OIDCProxy with mock validator', function() {
  this.timeout(10_000);

  let hostport: string;

  before(() => {
    if (!process.env.MONGODB_HOSTPORT) {
      throw new Error('MONGODB_HOSTPORT not set');
    }
    hostport = process.env.MONGODB_HOSTPORT;
  });

  describe('successful authentication via saslStart', () => {
    before(async () => {
      const client = new MongoClient(`mongodb://${hostport}`);
      await client.connect();
      try {
        await client.db('admin').command({
          createRole: 'test-user@example.com',
          privileges: [],
          roles: []
        });
      } catch (err: any) {
        if (err.code !== 11000 && !err.message.includes('already exists')) {
          throw err;
        }
      } finally {
        await client.close();
      }
    });

    it('authenticates when JWT is valid in saslStart payload', async () => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        email: 'test-user@example.com',
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

      const client = new net.Socket();
      const connectionPromise = once(proxy, 'newConnection');

      client.connect(addr.port, 'localhost');
      const [conn] = await connectionPromise;

      const authSuccessPromise = once(conn, 'authSuccess');
      const responsePromise = waitForResponse(client);

      // Send saslStart with a JWT in payload
      const msg = buildOpMsg({
        saslStart: 1,
        mechanism: 'MONGODB-OIDC',
        payload: new Binary(Buffer.from(serialize({ jwt: 'mock.jwt.token' }))),
        $db: 'admin'
      });
      client.write(msg);

      const [user, subject] = await authSuccessPromise;
      assert.strictEqual(user, 'test-user@example.com');
      assert(subject.includes('test-user@example.com'));
      assert.strictEqual(conn.getUser(), 'test-user@example.com');

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
    it('returns IdP info when no JWT in payload', async () => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        email: 'test-user@example.com',
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
    it('emits commandForwarded event on successful forward', async () => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        email: 'test-user@example.com',
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
      const reader = new ResponseReader(client);
      await new Promise<void>((resolve) => client.connect(addr.port, 'localhost', resolve));

      const [conn] = await once(proxy, 'newConnection');
      const commandForwardedPromise = once(conn, 'commandForwarded');

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

      const [user, dbName, cmdName, , , requestBytes, responseBytes] = await commandForwardedPromise;
      assert.strictEqual(user, 'test-user@example.com');
      assert.strictEqual(dbName, 'test');
      assert.strictEqual(cmdName, 'find');
      assert.strictEqual(typeof requestBytes, 'number');
      assert.strictEqual(typeof responseBytes, 'number');
      assert(requestBytes > 0);
      assert(responseBytes > 0);

      client.destroy();
      await proxy.stop();
    });
  });

  describe('token expiration handling', () => {
    it('returns reauth error when token is expired', async () => {
      const mockValidator = new MockJWTValidator({
        valid: true,
        subject: 'test-user@example.com',
        email: 'test-user@example.com',
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

      const client = new net.Socket();
      const reader = new ResponseReader(client);
      await new Promise<void>((resolve) => client.connect(addr.port, 'localhost', resolve));

      const [conn] = await once(proxy, 'newConnection');
      const reauthPromise = once(conn, 'reauthRequired');

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

      const [user, reason] = await reauthPromise;
      assert.strictEqual(user, 'test-user@example.com');
      assert(reason.includes('expired'));

      client.destroy();
      await proxy.stop();
    });

    it('returns reauth error when saslStart JWT is expired', async () => {
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
    it('returns error when email claim is missing', async () => {
      const mockValidator = new MockJWTValidator({
        valid: false,
        errorCode: JWTValidationError.INVALID,
        error: 'Email claim is required in JWT'
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
          payload: new Binary(Buffer.from(serialize({ jwt: 'no.email.jwt.token' }))),
          $db: 'admin'
        });
        client.write(msg);
      });

      const response = await responsePromise;
      const parsed = deserialize(response.subarray(21));

      // It should fall back to IdP info for retry, or return error?
      // Current OIDCProxy logic for !result.valid in saslStart:
      // if (result.errorCode === JWTValidationError.EXPIRED) -> sendReauthRequired (391)
      // otherwise -> return IdP info (ok: 1, done: false)
      assert.strictEqual(parsed.ok, 1);
      assert.strictEqual(parsed.done, false);

      client.destroy();
      await proxy.stop();
    });

    it('returns error when JWT is invalid in saslStart', async () => {
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
