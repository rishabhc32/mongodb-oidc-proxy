import net, { Server, Socket, AddressInfo } from 'net';
import { URL } from 'url';
import { EventEmitter } from 'events';
import { MongoClient, Document } from 'mongodb';
import { deserialize, Long } from 'bson';
import { LRUCache } from 'lru-cache';
import { WireProtocolParser } from '@src/parse-stream';
import { FullMessage, MAX_MESSAGE_SIZE_BYTES, getSaslCommand, getCommandDb, getCommandBody } from '@src/parse';
import { JWTValidator, JWTValidationError } from '@src/oidc/jwt-validator';
import { MessageBuilder } from '@src/oidc/message-builder';
import { SharedClientPool } from '@src/oidc/shared-client-pool';
import { randomBytes } from '@src/utils/random';
import { ksuid } from '@src/utils/ksuid';
import type { OIDCProxyConfig, IdpInfo } from '@src/oidc/types';
import type { UserProvisioner, UserClientLease, ProvisionResult } from '@src/oidc/user-provisioner';

const DEFAULT_MAX_CONNECTIONS = 10000;
const DEFAULT_CONNECTION_TIMEOUT_MS = 120000;
const PASSWORD_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
// Fits within the 10 seconds `docker stop` waits before killing the process
const DEFAULT_DRAIN_TIMEOUT_MS = 5000;

// Stored in customData of MongoDB users the proxy creates, so it never resets
// the password or roles of a user it does not own
const MANAGED_USER_MARKER = 'mongodb-oidc-proxy';

interface BackendInfo {
  protocol: string;
  host: string;
  params: URLSearchParams;
}

// True if the proxy created this user, so it may reset the user's password and roles.
// Users created before the marker existed are marked by ops/mark-managed-users.js
function isManagedUser(user: Document): boolean {
  return user.customData?.managedBy === MANAGED_USER_MARKER;
}

export class OIDCProxy extends EventEmitter implements UserProvisioner {
  private readonly server: Server;
  private readonly backendClient: MongoClient;
  private readonly jwtValidator: JWTValidator;
  private readonly messageBuilder: MessageBuilder;
  private readonly connections = new Set<OIDCConnection>();
  private readonly userClients = new SharedClientPool();
  private readonly maxConnections: number;
  private readonly maxConnectionsPerUser?: number;
  private readonly connectionTimeoutMs: number;
  private readonly backendInfo: BackendInfo;
  private readonly userPasswordCache = new LRUCache<string, string>({
    max: DEFAULT_MAX_CONNECTIONS,
    ttl: PASSWORD_CACHE_TTL_MS
  });

  private readonly idpInfo: IdpInfo;
  private readonly listenPort: number;
  private readonly listenHost?: string;

  constructor(config: OIDCProxyConfig, jwtValidator?: JWTValidator) {
    super();
    this.maxConnections = config.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
    this.maxConnectionsPerUser = config.maxConnectionsPerUser;
    this.connectionTimeoutMs = config.connectionTimeoutMs ?? DEFAULT_CONNECTION_TIMEOUT_MS;
    this.jwtValidator =
      jwtValidator ?? new JWTValidator(config.issuer, config.clientId, config.jwksUri, config.audience);
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
    this.server = net.createServer((socket) => this.handleConnection(socket));
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

  // Stops accepting connections and closes every open one, letting commands already
  // received finish for up to `drainTimeoutMs`. Closing the backend clients then
  // interrupts any command still running, and stop() resolves once each has been reported
  async stop(drainTimeoutMs = DEFAULT_DRAIN_TIMEOUT_MS): Promise<void> {
    // Resolves once every connection has closed, or at once if the server is not listening
    const serverClosed = new Promise<void>((resolve) => this.server.close(() => resolve()));
    const connections = [...this.connections];

    await Promise.allSettled(connections.map((conn) => conn.close(drainTimeoutMs)));
    await Promise.allSettled([serverClosed, this.backendClient.close(), this.userClients.closeAll()]);
    await Promise.allSettled(connections.map((conn) => conn.idle()));
  }

  address(): AddressInfo | string | null {
    return this.server.address();
  }

  // Authorizes the user and leases the backend client shared by their connections.
  // `current` is the lease the calling connection already holds, if any
  async provisionUser(
    email: string,
    current: UserClientLease | undefined,
    debug: (message: string) => void
  ): Promise<ProvisionResult> {
    debug(`Checking roles for ${email}...`);
    const error = await this.authorizeUser(email);
    if (error) {
      return { error };
    }

    // Reauthenticating as the same user swaps one lease for another
    const held = current?.email === email ? 1 : 0;
    if (
      this.maxConnectionsPerUser !== undefined &&
      this.userClients.connectionCount(email) - held >= this.maxConnectionsPerUser
    ) {
      return { error: `Too many connections for user '${email}'` };
    }

    return { lease: await this.userClients.acquire(email, () => this.connectUserClient(email, debug)) };
  }

  private async authorizeUser(email: string): Promise<string | null> {
    const adminDb = this.backendClient.db('admin');

    // Built-in roles (root, readWriteAnyDatabase, ...) are never granted from a token
    const rolesInfo = await adminDb.command({ rolesInfo: { role: email, db: 'admin' } });
    const role = rolesInfo.roles?.[0];
    if (!role || role.isBuiltin) {
      return `Role '${email}' not defined`;
    }

    const usersInfo = await adminDb.command({ usersInfo: { user: email, db: 'admin' } });
    const user = usersInfo.users?.[0];
    if (user && !isManagedUser(user)) {
      return `User '${email}' exists and is not managed by the proxy`;
    }

    return null;
  }

  private async connectUserClient(email: string, debug: (message: string) => void): Promise<MongoClient> {
    const password = await this.ensureUserPassword(email, debug);
    const { protocol, host, params } = this.backendInfo;
    return new MongoClient(
      `${protocol}//${encodeURIComponent(email)}:${encodeURIComponent(password)}@${host}/?${params.toString()}`
    ).connect();
  }

  // Only called while creating a user's shared client, which the pool does at
  // most once at a time per user, so concurrent logins never race here
  private async ensureUserPassword(email: string, debug: (message: string) => void): Promise<string> {
    const cachedPassword = this.userPasswordCache.get(email);
    if (cachedPassword) {
      debug(`User found in cache ${email}`);
      return cachedPassword;
    }

    const adminDb = this.backendClient.db('admin');

    // Create/Update user with random password
    const password = randomBytes(32).toString('base64');
    const user = {
      pwd: password,
      roles: [{ role: email, db: 'admin' }],
      customData: { managedBy: MANAGED_USER_MARKER }
    };

    try {
      await adminDb.command({ updateUser: email, ...user });
      debug(`Updated user ${email}`);
    } catch (err: any) {
      if (err.codeName === 'UserNotFound') {
        await adminDb.command({ createUser: email, ...user });
        debug(`Created user ${email}`);
      } else {
        throw err;
      }
    }

    // Set the new password in the cache
    this.userPasswordCache.set(email, password);
    return password;
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
      this.jwtValidator,
      this.messageBuilder,
      this,
      this.idpInfo
    );

    this.connections.add(conn);

    conn.on('connectionClosed', () => {
      this.connections.delete(conn);
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
  private lease?: UserClientLease;
  private closing = false;
  private readonly inFlight = new Set<Promise<void>>();
  private conversationId = 0;
  private authenticated = false;
  private subject?: string;
  private email?: string;
  private tokenExp?: number;
  private jwtValidator: JWTValidator;
  private messageBuilder: MessageBuilder;
  private provisioner: UserProvisioner;
  private idpInfo: IdpInfo;

  constructor(
    id: string,
    incoming: string,
    socket: Socket,
    timeoutMs: number,
    jwtValidator: JWTValidator,
    messageBuilder: MessageBuilder,
    provisioner: UserProvisioner,
    idpInfo: IdpInfo
  ) {
    super();
    this.connId = id;
    this.incoming = incoming;
    this.bytesIn = 0;
    this.bytesOut = 0;
    this.socket = socket;
    this.jwtValidator = jwtValidator;
    this.messageBuilder = messageBuilder;
    this.provisioner = provisioner;
    this.idpInfo = idpInfo;
    // Compression is never advertised, and decompressing before auth is a DoS vector
    this.parser = new WireProtocolParser({ allowCompressed: false });

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
      if (this.closing) {
        return;
      }
      const handled: Promise<void> = this.handleMessage(msg)
        .catch((err: Error) => {
          // Fail only this request; an unhandled 'error' event would crash the proxy.
          // Details go to the log, not to the (possibly unauthenticated) client
          this.emit('connectionError', err);
          this.write(this.messageBuilder.buildErrorResponse(msg.header.requestID, 'Internal proxy error'));
        })
        .finally(() => this.inFlight.delete(handled));
      this.inFlight.add(handled);
    });

    // A malformed message leaves the stream unparseable, so drop the connection
    this.parser.on('error', (err: Error) => {
      this.emit('parseError', err);
      this.socket.destroy();
    });

    this.socket.pipe(this.parser);

    // Clean up on socket close
    this.socket.on('close', () => {
      this.emit('connectionClosed');
      this.replaceLease(undefined);
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

  // Stops reading requests, gives the ones already received up to `timeoutMs` to
  // finish and reply, then closes the socket. Requests the client sends meanwhile are dropped
  async close(timeoutMs: number): Promise<void> {
    this.closing = true;
    this.socket.unpipe(this.parser);
    if (this.socket.closed) {
      return;
    }

    const closed = new Promise<void>((resolve) => this.socket.once('close', () => resolve()));
    const deadline = setTimeout(() => this.socket.destroy(), timeoutMs);
    await Promise.race([this.idle(), closed]);
    if (!this.socket.destroyed) {
      // end() sends the replies still queued; destroy() would discard them
      this.socket.end(() => this.socket.destroy());
    }
    await closed;
    clearTimeout(deadline);
  }

  // Resolves once every request received so far has been handled
  async idle(): Promise<void> {
    await Promise.allSettled(this.inFlight);
  }

  private write(buffer: Buffer): void {
    if (this.socket.destroyed) {
      return;
    }
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
        const lease = await this.provisionUser(msg.header.requestID, email);
        if (!lease) {
          return;
        }

        // Authentication successful
        this.replaceLease(lease);
        this.authenticated = true;
        this.email = email;
        this.subject = result.subject;
        this.tokenExp = result.exp;

        this.write(this.messageBuilder.buildAuthSuccessResponse(msg.header.requestID, this.conversationId));
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
    this.write(this.messageBuilder.buildSaslStartResponse(msg.header.requestID, this.conversationId, this.idpInfo));
    this.emit('saslStart', this.idpInfo);
  }

  private async handleSaslContinue(msg: FullMessage, payload?: Uint8Array, conversationId?: number): Promise<void> {
    // Validate conversationId matches the one from saslStart
    if (conversationId !== this.conversationId) {
      this.write(this.messageBuilder.buildAuthFailureResponse(msg.header.requestID, 'Invalid conversationId'));
      return;
    }

    const jwt = this.extractJwtFromPayload(payload);
    if (!jwt) {
      this.write(this.messageBuilder.buildAuthFailureResponse(msg.header.requestID, 'Missing or invalid JWT payload'));
      return;
    }

    const decodedJwt = this.decodeJwtPayload(jwt);
    this.emit('authAttempt', decodedJwt?.email, decodedJwt);

    // Validate JWT
    const result = await this.jwtValidator.validate(jwt);
    if (!result.valid) {
      this.write(
        this.messageBuilder.buildAuthFailureResponse(msg.header.requestID, `Authentication failed: ${result.error}`)
      );
      this.emit('authFailed', result?.email, result.error);
      return;
    }

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const email = result.email!;
    const lease = await this.provisionUser(msg.header.requestID, email);
    if (!lease) {
      return;
    }

    // Authentication successful
    this.replaceLease(lease);
    this.authenticated = true;
    this.subject = result.subject;
    this.email = email;
    this.tokenExp = result.exp;

    this.write(this.messageBuilder.buildAuthSuccessResponse(msg.header.requestID, this.conversationId));
    this.emit('authSuccess', email, result.subject);
  }

  private async provisionUser(requestId: number, email: string): Promise<UserClientLease | null> {
    const result = await this.provisioner.provisionUser(email, this.lease, (message) =>
      this.emit('debug', email, message)
    );
    if ('error' in result) {
      this.emit('debug', email, result.error);
      this.write(this.messageBuilder.buildAuthFailureResponse(requestId, result.error));
      return null;
    }

    // The client may have disconnected while the user was being provisioned.
    // The socket close handler has already run, so nothing else would release this
    if (this.socket.destroyed) {
      result.lease.release();
      return null;
    }

    return result.lease;
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
    } catch {
      /* ignore */
    }
    return null;
  }

  private handleHello(msg: FullMessage): void {
    // Build a hello response that advertises OIDC auth and session support
    const helloResponse: Document = {
      ismaster: true,
      maxBsonObjectSize: 16777216,
      maxMessageSizeBytes: MAX_MESSAGE_SIZE_BYTES,
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
    const response =
      msg.contents.opCode === 'OP_QUERY'
        ? this.messageBuilder.buildOpReply(msg.header.requestID, helloResponse)
        : this.messageBuilder.buildCommandResponse(msg.header.requestID, helloResponse);
    this.write(response);
  }

  // Swap in a new lease on the user's backend client, releasing the previous one
  // so the shared client is closed once no connection uses it
  private replaceLease(lease: UserClientLease | undefined): void {
    const previous = this.lease;
    this.lease = lease;
    if (previous !== lease) {
      previous?.release();
    }
  }

  private sendReauthRequired(requestID: number, reason: string): void {
    this.authenticated = false;
    this.tokenExp = undefined;

    // Release the user's backend client; a lease is acquired again on reauth
    this.replaceLease(undefined);

    this.write(
      this.messageBuilder.buildErrorResponse(
        requestID,
        `Reauthentication required: ${reason}`,
        391,
        'ReauthenticationRequired'
      )
    );
    this.emit('reauthRequired', this.email, reason);
  }

  private async forwardCommand(msg: FullMessage): Promise<void> {
    // Capture the lease before any await: the connection can reauthenticate as
    // another user while this command runs, and the command must run and be
    // logged as the user who sent it
    const lease = this.lease;
    if (!lease) {
      this.write(this.messageBuilder.buildAuthFailureResponse(msg.header.requestID, 'Authentication required', 13));
      return;
    }

    const dbName = getCommandDb(msg) || 'admin';
    const body = getCommandBody(msg);
    const cmdName = this.getCommandName(body);

    if (!body) {
      const response = this.messageBuilder.buildErrorResponse(msg.header.requestID, 'Invalid command format');
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

    const command = { ...body };
    delete command.$db;

    try {
      // Use the user's own backend client
      const result = await lease.client.db(dbName).command(command as Document);

      // Ensure cursor.id is a proper BSON Long type for mongosh compatibility
      if (result.cursor && result.cursor.id !== undefined) {
        const cursorId = result.cursor.id;
        if (typeof cursorId === 'bigint') {
          result.cursor.id = Long.fromBigInt(cursorId);
        } else if (typeof cursorId === 'number') {
          result.cursor.id = Long.fromNumber(cursorId);
        }
      }

      const response = this.messageBuilder.buildCommandResponse(msg.header.requestID, result);
      this.write(response);

      const requestBytes = msg.header?.messageLength ?? 0;
      const responseBytes = response.length;
      this.emit('commandForwarded', lease.email, dbName, cmdName, command, result, requestBytes, responseBytes);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      const response = this.messageBuilder.buildErrorResponse(msg.header.requestID, errorMessage);
      this.write(response);
      this.emit('commandError', lease.email, errorMessage, dbName, cmdName, command);
    }
  }
}
