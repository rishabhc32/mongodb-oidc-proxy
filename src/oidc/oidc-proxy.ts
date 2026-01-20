import net, { Server, Socket, AddressInfo } from 'net';
import { URL } from 'url';
import { EventEmitter } from 'events';
import { promisify } from 'util';
import { MongoClient, Document } from 'mongodb';
import { deserialize, Long } from 'bson';
import { LRUCache } from 'lru-cache';
import { WireProtocolParser } from '@src/parse-stream';
import { FullMessage, getSaslCommand, getCommandDb, getCommandBody } from '@src/parse';
import { JWTValidator, JWTValidationError } from '@src/oidc/jwt-validator';
import { MessageBuilder } from '@src/oidc/message-builder';
import { Singleflight } from '@src/utils/sync';
import { randomBytes } from '@src/utils/random';
import { ksuid } from '@src/utils/ksuid';
import type { OIDCProxyConfig, IdpInfo } from '@src/oidc/types';

const DEFAULT_MAX_CONNECTIONS = 10000;
const DEFAULT_CONNECTION_TIMEOUT_MS = 120000;
const PASSWORD_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

interface BackendInfo {
  protocol: string;
  host: string;
  params: URLSearchParams;
}

export class OIDCProxy extends EventEmitter {
  private server: Server;
  private backendClient: MongoClient;
  private jwtValidator: JWTValidator;
  private messageBuilder: MessageBuilder;
  private connections: Map<string, OIDCConnection> = new Map();
  private maxConnections: number;
  private connectionTimeoutMs: number;
  private backendInfo: BackendInfo;
  private singleflight = new Singleflight();
  private userPasswordCache = new LRUCache<string, string>({
    max: DEFAULT_MAX_CONNECTIONS,
    ttl: PASSWORD_CACHE_TTL_MS
  });

  private idpInfo: IdpInfo;
  private listenPort: number;
  private listenHost?: string;

  constructor(config: OIDCProxyConfig, jwtValidator?: JWTValidator) {
    super();
    this.maxConnections = config.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
    this.connectionTimeoutMs = config.connectionTimeoutMs ?? DEFAULT_CONNECTION_TIMEOUT_MS;
    this.jwtValidator = jwtValidator ?? new JWTValidator(config.issuer, config.clientId, config.jwksUri, config.audience);
    this.messageBuilder = new MessageBuilder();
    this.idpInfo = { issuer: config.issuer, clientId: config.clientId };
    this.listenPort = config.listenPort;
    this.listenHost = config.listenHost;

    const url = new URL(config.connectionString);
    const params = url.searchParams;
    params.set('authSource', 'admin');

    this.backendInfo = {
      protocol: url.protocol,
      host: url.host,
      params
    };

    this.backendClient = new MongoClient(config.connectionString);
    this.server = net.createServer(socket => this.handleConnection(socket));
  }

  async start(): Promise<void> {
    await this.backendClient.connect();
    this.emit('backendConnected');

    return new Promise((resolve, reject) => {
      this.server.listen(this.listenPort, this.listenHost || 'localhost', () => {
        this.emit('listening', this.server.address());
        resolve();
      });
      this.server.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    for (const conn of this.connections.values()) {
      conn.emit('connectionClosed');
    }

    const closeServer = promisify(this.server.close.bind(this.server));
    await Promise.allSettled([
      closeServer(),
      this.backendClient.close()
    ]);
  }

  address(): AddressInfo | string | null {
    return this.server.address();
  }

  private handleConnection(socket: Socket): void {
    const connId = ksuid();

    // Reject if max connections exceeded
    if (this.connections.size >= this.maxConnections) {
      socket.destroy();
      return;
    }

    const remoteAddr = `${socket.remoteAddress}:${socket.remotePort}`;
    const conn = new OIDCConnection(
      connId,
      remoteAddr,
      socket,
      this.connectionTimeoutMs,
      this.backendClient,
      this.jwtValidator,
      this.messageBuilder,
      this.userPasswordCache,
      this.singleflight,
      this.backendInfo,
      this.idpInfo
    );

    this.connections.set(connId, conn);

    conn.on('connectionClosed', () => {
      this.connections.delete(connId);
    });

    this.emit('newConnection', conn);
  }
}

export class OIDCConnection extends EventEmitter {
  connId: string;
  incoming: string;
  bytesIn: number;
  bytesOut: number;

  private socket: Socket;
  private parser: WireProtocolParser;
  private userClient?: MongoClient;
  private conversationId = 0;
  private authenticated = false;
  private subject?: string;
  private email?: string;
  private tokenExp?: number;
  private backendClient: MongoClient;
  private jwtValidator: JWTValidator;
  private messageBuilder: MessageBuilder;
  private userPasswordCache: LRUCache<string, string>;
  private singleflight: Singleflight;
  private backendInfo: BackendInfo;
  private idpInfo: IdpInfo;

  constructor(
    id: string,
    incoming: string,
    socket: Socket,
    timeoutMs: number,
    backendClient: MongoClient,
    jwtValidator: JWTValidator,
    messageBuilder: MessageBuilder,
    userPasswordCache: LRUCache<string, string>,
    singleflight: Singleflight,
    backendInfo: BackendInfo,
    idpInfo: IdpInfo
  ) {
    super();
    this.connId = id;
    this.incoming = incoming;
    this.bytesIn = 0;
    this.bytesOut = 0;
    this.socket = socket;
    this.backendClient = backendClient;
    this.jwtValidator = jwtValidator;
    this.messageBuilder = messageBuilder;
    this.userPasswordCache = userPasswordCache;
    this.singleflight = singleflight;
    this.backendInfo = backendInfo;
    this.idpInfo = idpInfo;
    this.parser = new WireProtocolParser();

    this.setupSocket(timeoutMs);
  }

  private getCommandName(command?: Record<string, unknown> | null): string | null {
    if (!command) {
      return null;
    }
    return Object.keys(command).find((key) => !key.startsWith('$')) ?? null;
  }

  private setupSocket(timeoutMs: number): void {
    // Set idle timeout
    this.socket.setTimeout(timeoutMs, () => {
      this.emit('connectionTimeout');
      this.socket.destroy();
    });

    // Track incoming bandwidth
    this.socket.on('data', (chunk: Buffer) => {
      this.bytesIn += chunk.length;
    });

    this.parser.on('message', (msg: FullMessage) => {
      this.handleMessage(msg).catch(err => {
        this.emit('error', err);
      });
    });

    this.parser.on('error', (err: Error) => {
      this.emit('parseError', err);
    });

    this.socket.pipe(this.parser);

    // Clean up on socket close
    this.socket.on('close', async () => {
      this.emit('connectionClosed');
      if (this.userClient) {
        await this.userClient.close().catch(() => { });
      }
      this.parser.destroy();
    });

    // On error, destroy socket (triggers close event for cleanup)
    this.socket.on('error', (err: Error) => {
      this.emit('connectionError', err);
      this.socket.destroy();
    });
  }

  toJSON() {
    return {
      id: this.connId,
      incoming: this.incoming,
      bytesIn: this.bytesIn,
      bytesOut: this.bytesOut
    };
  }

  getUser(): string | undefined {
    return this.email;
  }

  private write(buffer: Buffer): void {
    this.bytesOut += buffer.length;
    this.socket.write(buffer);
  }

  private async handleMessage(msg: FullMessage): Promise<void> {
    const opCode = msg.contents.opCode;

    // Handle legacy OP_QUERY (used by older drivers for ismaster)
    if (opCode === 'OP_QUERY') {
      const query = msg.contents as any;
      if (query.query?.data?.ismaster || query.query?.data?.isMaster || query.fullCollectionName?.endsWith('.$cmd')) {
        this.handleHello(msg);
        return;
      }
    }

    const saslCmd = getSaslCommand(msg);

    // Handle OIDC authentication
    if (saslCmd.type === 'saslStart' && saslCmd.mechanism === 'MONGODB-OIDC') {
      await this.handleSaslStart(msg, saslCmd.payload);
      return;
    }

    if (saslCmd.type === 'saslContinue') {
      await this.handleSaslContinue(msg, saslCmd.payload, saslCmd.conversationId);
      return;
    }

    // For non-auth commands, check if authenticated
    if (!this.authenticated) {
      const body = getCommandBody(msg);
      const cmdName = this.getCommandName(body);

      // Allow hello/ismaster without auth for driver handshake
      if (body && (body.hello || body.ismaster || body.isMaster)) {
        this.handleHello(msg);
        return;
      }

      // Allow ping without auth
      if (body && body.ping) {
        const response = this.messageBuilder.buildCommandResponse(msg.header.requestID, { ok: 1 });
        this.write(response);
        return;
      }

      this.emit('authRequired', cmdName);
      const response = this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        'Authentication required',
        13
      );
      this.write(response);
      return;
    }

    // Forward authenticated commands to backend
    await this.forwardCommand(msg);
  }

  private async handleSaslStart(msg: FullMessage, payload?: Uint8Array): Promise<void> {
    ++this.conversationId;

    // Try to authenticate with JWT from payload
    const jwt = this.extractJwtFromPayload(payload);
    if (jwt) {
      const decodedJwt = this.decodeJwtPayload(jwt);
      this.emit('authAttempt', decodedJwt?.email, decodedJwt);

      const result = await this.jwtValidator.validate(jwt);
      if (result.valid) {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const email = result.email!;
        const userClient = await this.provisionUser(msg.header.requestID, email);
        if (!userClient) {
          return;
        }

        // Authentication successful
        this.userClient = userClient;
        this.authenticated = true;
        this.email = email;
        this.subject = result.subject;
        this.tokenExp = result.exp;

        this.write(this.messageBuilder.buildAuthSuccessResponse(
          msg.header.requestID,
          this.conversationId
        ));
        this.emit('authSuccess', email, this.subject);
        return;
      }

      this.emit('debug', result?.email, `JWT validation failed: ${result.errorCode} - ${result.error}`);

      if (result.errorCode === JWTValidationError.EXPIRED) {
        this.sendReauthRequired(msg.header.requestID, 'access token has expired');
        return;
      }
    }

    // No JWT or validation failed - return IdP info for OIDC flow
    this.write(this.messageBuilder.buildSaslStartResponse(
      msg.header.requestID,
      this.conversationId,
      this.idpInfo
    ));
    this.emit('saslStart', this.idpInfo);
  }

  private async handleSaslContinue(msg: FullMessage, payload?: Uint8Array, conversationId?: number): Promise<void> {
    // Validate conversationId matches the one from saslStart
    if (conversationId !== this.conversationId) {
      this.write(this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        'Invalid conversationId'
      ));
      return;
    }

    const jwt = this.extractJwtFromPayload(payload);
    if (!jwt) {
      this.write(this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        'Missing or invalid JWT payload'
      ));
      return;
    }

    const decodedJwt = this.decodeJwtPayload(jwt);
    this.emit('authAttempt', decodedJwt?.email, decodedJwt);

    // Validate JWT
    const result = await this.jwtValidator.validate(jwt);
    if (!result.valid) {
      this.write(this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        `Authentication failed: ${result.error}`
      ));
      this.emit('authFailed', result?.email, result.error);
      return;
    }

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const email = result.email!;
    const userClient = await this.provisionUser(msg.header.requestID, email);
    if (!userClient) {
      return;
    }

    // Authentication successful
    this.userClient = userClient;
    this.authenticated = true;
    this.subject = result.subject;
    this.email = email;
    this.tokenExp = result.exp;

    this.write(this.messageBuilder.buildAuthSuccessResponse(
      msg.header.requestID,
      this.conversationId
    ));
    this.emit('authSuccess', email, result.subject);
  }

  private async provisionUser(requestId: number, email: string): Promise<MongoClient | null> {
    const { value } = await this.singleflight.do(email, async () => {
      this.emit('debug', email, `Checking roles for ${email}...`);
      const adminDb = this.backendClient.db('admin');

      // Verify role exists
      const rolesInfo = await adminDb.command({ rolesInfo: email });
      if (!rolesInfo.roles || rolesInfo.roles.length === 0) {
        this.emit('debug', email, `Role ${email} not found in DB`);
        this.socket.write(this.messageBuilder.buildAuthFailureResponse(
          requestId,
          `Role '${email}' not defined`
        ));
        return null;
      }

      const cachedPassword = this.userPasswordCache.get(email);
      if (cachedPassword) {
        this.emit('debug', email, `User found in cache ${email}`);
        return {
          username: email,
          password: cachedPassword
        };
      }

      // Create/Update user with random password
      const password = randomBytes(32).toString('base64');

      try {
        await adminDb.command({
          updateUser: email,
          pwd: password,
          roles: [{ role: email, db: 'admin' }]
        });
        this.emit('debug', email, `Updated user ${email}`);
      } catch (err: any) {
        if (err.codeName === 'UserNotFound') {
          await adminDb.command({
            createUser: email,
            pwd: password,
            roles: [{ role: email, db: 'admin' }]
          });
          this.emit('debug', email, `Created user ${email}`);
        } else {
          throw err;
        }
      }

      // Set the new password in the cache
      this.userPasswordCache.set(email, password);

      return {
        username: email,
        password: password
      };
    });

    if (!value) {
      return null;
    }

    const { protocol, host, params } = this.backendInfo;
    return new MongoClient(
      `${protocol}//${encodeURIComponent(value.username)}:${encodeURIComponent(value.password)}@${host}/?${params.toString()}`
    ).connect();
  }

  private extractJwtFromPayload(payload?: Uint8Array): string | null {
    if (!payload || payload.length === 0) {
      this.emit('debug', null, 'saslStart with empty payload');
      return null;
    }

    let payloadDoc: Record<string, unknown>;
    try {
      payloadDoc = deserialize(payload);
    } catch (err) {
      this.emit('debug', null, `saslStart payload parse error: ${err}`);
      return null;
    }

    const jwt = payloadDoc.jwt as string | undefined;
    if (!jwt) {
      this.emit('debug', null, 'saslStart payload has no jwt field');
      return null;
    }

    return jwt;
  }

  private decodeJwtPayload(jwt: string): Record<string, unknown> | null {
    try {
      const parts = jwt.split('.');
      if (parts.length === 3) {
        return JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      }
    } catch { /* ignore */ }
    return null;
  }

  private handleHello(msg: FullMessage): void {
    // Build a hello response that advertises OIDC auth and session support
    const helloResponse: Document = {
      ismaster: true,
      maxBsonObjectSize: 16777216,
      maxMessageSizeBytes: 48000000,
      maxWriteBatchSize: 100000,
      localTime: new Date(),
      logicalSessionTimeoutMinutes: 30,
      minWireVersion: 0,
      maxWireVersion: 21,
      readOnly: false,
      saslSupportedMechs: ['MONGODB-OIDC'],
      ok: 1
    };

    // Use OP_REPLY for legacy OP_QUERY, OP_MSG for modern messages
    const response = msg.contents.opCode === 'OP_QUERY'
      ? this.messageBuilder.buildOpReply(msg.header.requestID, helloResponse)
      : this.messageBuilder.buildCommandResponse(msg.header.requestID, helloResponse);
    this.write(response);
  }

  private sendReauthRequired(requestID: number, reason: string): void {
    this.authenticated = false;
    this.tokenExp = undefined;

    this.write(this.messageBuilder.buildErrorResponse(
      requestID,
      `Reauthentication required: ${reason}`,
      391,
      'ReauthenticationRequired'
    ));
    this.emit('reauthRequired', this.email, reason);
  }

  private async forwardCommand(msg: FullMessage): Promise<void> {
    const dbName = getCommandDb(msg) || 'admin';
    const body = getCommandBody(msg);
    const cmdName = this.getCommandName(body);

    if (!body) {
      const response = this.messageBuilder.buildErrorResponse(
        msg.header.requestID,
        'Invalid command format'
      );
      this.write(response);
      return;
    }

    // Check if token has expired - return ReauthenticationRequired (code 391) if so
    // This allows compliant drivers to reauthenticate without dropping the connection
    const tokenExp = this.tokenExp;
    if (tokenExp && Math.floor(Date.now() / 1000) >= tokenExp) {
      this.sendReauthRequired(msg.header.requestID, `command ${cmdName} - token expired`);
      return;
    }

    try {
      const command = { ...body };
      delete command.$db;

      // Use the dedicated user client
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const result = await this.userClient!.db(dbName).command(command as Document);

      // Ensure cursor.id is a proper BSON Long type for mongosh compatibility
      if (result.cursor && result.cursor.id !== undefined) {
        const cursorId = result.cursor.id;
        if (typeof cursorId === 'bigint') {
          result.cursor.id = Long.fromBigInt(cursorId);
        } else if (typeof cursorId === 'number') {
          result.cursor.id = Long.fromNumber(cursorId);
        }
      }

      const response = this.messageBuilder.buildCommandResponse(
        msg.header.requestID,
        result
      );
      this.write(response);

      const requestBytes = msg.header?.messageLength ?? 0;
      const responseBytes = response.length;
      this.emit(
        'commandForwarded',
        this.email,
        dbName,
        cmdName,
        command,
        result,
        requestBytes,
        responseBytes
      );
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      const response = this.messageBuilder.buildErrorResponse(
        msg.header.requestID,
        errorMessage
      );
      this.write(response);
      this.emit('commandError', this.email, errorMessage, dbName, cmdName);
    }
  }
}
