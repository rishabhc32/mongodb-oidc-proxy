import net from 'net';
import * as crypto from 'crypto';
import { URL } from 'url';
import { EventEmitter } from 'events';
import { MongoClient, Document } from 'mongodb';
import { deserialize, Long } from 'bson';
import { WireProtocolParser } from '../parse-stream';
import { FullMessage, getSaslCommand, getCommandDb, getCommandBody } from '../parse';
import { JWTValidator, JWTValidationError } from './jwt-validator';
import { MessageBuilder } from './message-builder';
import type { OIDCProxyConfig, OIDCAuthState, IdpInfo } from './types';

interface ConnectionState {
  id: number;
  socket: net.Socket;
  parser: WireProtocolParser;
  authState: OIDCAuthState;
  userClient?: MongoClient;
}

interface BackendInfo {
  protocol: string;
  host: string;
  params: URLSearchParams;
}

const DEFAULT_MAX_CONNECTIONS = 10000;
const DEFAULT_CONNECTION_TIMEOUT_MS = 120000;

export class OIDCProxy extends EventEmitter {
  private server: net.Server;
  private backendClient: MongoClient;
  private jwtValidator: JWTValidator;
  private messageBuilder: MessageBuilder;
  private config: OIDCProxyConfig;
  private connections: Map<number, ConnectionState> = new Map();
  private connectionIdCounter = 0;
  private conversationIdCounter = 0;
  private maxConnections: number;
  private connectionTimeoutMs: number;
  private backendInfo: BackendInfo;

  constructor(config: OIDCProxyConfig, jwtValidator?: JWTValidator) {
    super();
    this.config = config;
    this.maxConnections = config.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
    this.connectionTimeoutMs = config.connectionTimeoutMs ?? DEFAULT_CONNECTION_TIMEOUT_MS;
    this.jwtValidator = jwtValidator ?? new JWTValidator(config.issuer, config.clientId, config.jwksUri, config.audience);
    this.messageBuilder = new MessageBuilder();

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
      this.server.listen(this.config.listenPort, this.config.listenHost || 'localhost', () => {
        this.emit('listening', this.server.address());
        resolve();
      });
      this.server.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    for (const conn of this.connections.values()) {
      conn.socket.destroy();
    }
    this.connections.clear();

    await new Promise<void>((resolve) => {
      this.server.close(() => resolve());
    });

    await this.backendClient.close();
  }

  address(): net.AddressInfo | string | null {
    return this.server.address();
  }

  private handleConnection(socket: net.Socket): void {
    const connId = ++this.connectionIdCounter;

    // Reject if max connections exceeded
    if (this.connections.size >= this.maxConnections) {
      socket.destroy();
      return;
    }

    // Set idle timeout
    socket.setTimeout(this.connectionTimeoutMs, () => {
      this.emit('connectionTimeout', connId);
      socket.destroy();
    });

    const parser = new WireProtocolParser();

    const connState: ConnectionState = {
      id: connId,
      socket,
      parser,
      authState: {
        conversationId: 0,
        authenticated: false
      }
    };

    this.connections.set(connId, connState);

    const remoteAddr = `${socket.remoteAddress}:${socket.remotePort}`;
    this.emit('newConnection', { id: connId, incoming: remoteAddr });

    parser.on('message', (msg: FullMessage) => {
      this.handleClientMessage(connState, msg).catch(err => {
        this.emit('error', connId, err);
      });
    });

    parser.on('error', (err: Error) => {
      this.emit('parseError', connId, err);
    });

    socket.pipe(parser);

    // Clean up on socket close
    socket.on('close', async () => {
      this.emit('connectionClosed', connId);
      if (connState.userClient) {
        await connState.userClient.close().catch(() => { });
      }
      this.connections.delete(connId);
      parser.destroy();
    });

    // On error, destroy socket (triggers close event for cleanup)
    socket.on('error', (err: Error) => {
      this.emit('connectionError', connId, err);
      socket.destroy();
    });
  }

  private async handleClientMessage(connState: ConnectionState, msg: FullMessage): Promise<void> {
    const opCode = msg.contents.opCode;

    // Handle legacy OP_QUERY (used by older drivers for ismaster)
    if (opCode === 'OP_QUERY') {
      const query = msg.contents as any;
      if (query.query?.data?.ismaster || query.query?.data?.isMaster || query.fullCollectionName?.endsWith('.$cmd')) {
        await this.handleHello(connState, msg);
        return;
      }
    }

    const saslCmd = getSaslCommand(msg);

    // Handle OIDC authentication
    if (saslCmd.type === 'saslStart' && saslCmd.mechanism === 'MONGODB-OIDC') {
      await this.handleSaslStart(connState, msg, saslCmd.payload);
      return;
    }

    if (saslCmd.type === 'saslContinue') {
      await this.handleSaslContinue(connState, msg, saslCmd.payload, saslCmd.conversationId);
      return;
    }

    // For non-auth commands, check if authenticated
    if (!connState.authState.authenticated) {
      const body = getCommandBody(msg);
      const cmdName = body ? Object.keys(body).find(k => !k.startsWith('$')) : null;

      // Allow hello/ismaster without auth for driver handshake
      if (body && (body.hello || body.ismaster || body.isMaster)) {
        await this.handleHello(connState, msg);
        return;
      }

      // Allow ping without auth
      if (body && body.ping) {
        const response = this.messageBuilder.buildCommandResponse(msg.header.requestID, { ok: 1 });
        connState.socket.write(response);
        return;
      }

      this.emit('authRequired', connState.id, cmdName);
      const response = this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        'Authentication required',
        13
      );
      connState.socket.write(response);
      return;
    }

    // Forward authenticated commands to backend
    await this.forwardCommand(connState, msg);
  }

  private async handleSaslStart(connState: ConnectionState, msg: FullMessage, payload?: Uint8Array): Promise<void> {
    connState.authState.conversationId = ++this.conversationIdCounter;

    // Try to authenticate with JWT from payload
    const jwt = this.extractJwtFromPayload(connState.id, payload);
    if (jwt) {
      this.emit('debug', connState.id, 'saslStart has JWT, validating...');
      const result = await this.jwtValidator.validate(jwt);

      if (result.valid) {
        const email = result.email!;
        const success = await this.provisionUser(connState, msg.header.requestID, email);
        if (!success) {
          return;
        }

        connState.authState.authenticated = true;
        connState.authState.principalName = result.subject;
        connState.authState.email = email;
        connState.authState.tokenExp = result.exp;
        connState.socket.write(this.messageBuilder.buildAuthSuccessResponse(
          msg.header.requestID,
          connState.authState.conversationId
        ));
        this.emit('authSuccess', connState.id, `${result.subject} (${email}) (via saslStart)`);
        return;
      }

      this.emit('debug', connState.id, `JWT validation failed: ${result.errorCode} - ${result.error}`);

      if (result.errorCode === JWTValidationError.EXPIRED) {
        this.sendReauthRequired(connState, msg.header.requestID, 'access token has expired');
        return;
      }
    }

    // No JWT or validation failed - return IdP info for OIDC flow
    const idpInfo: IdpInfo = {
      issuer: this.config.issuer,
      clientId: this.config.clientId
    };
    connState.socket.write(this.messageBuilder.buildSaslStartResponse(
      msg.header.requestID,
      connState.authState.conversationId,
      idpInfo
    ));
    this.emit('saslStart', connState.id, idpInfo);
  }

  private async handleSaslContinue(
    connState: ConnectionState,
    msg: FullMessage,
    payload?: Uint8Array,
    conversationId?: number
  ): Promise<void> {
    // Validate conversationId matches the one from saslStart
    if (conversationId !== connState.authState.conversationId) {
      connState.socket.write(this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        'Invalid conversationId'
      ));
      return;
    }

    const jwt = this.extractJwtFromPayload(connState.id, payload);
    if (!jwt) {
      connState.socket.write(this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        'Missing or invalid JWT payload'
      ));
      return;
    }

    // Validate JWT
    const result = await this.jwtValidator.validate(jwt);
    if (!result.valid) {
      connState.socket.write(this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        `Authentication failed: ${result.error}`
      ));
      this.emit('authFailed', connState.id, result.error);
      return;
    }

    const email = result.email!;
    const success = await this.provisionUser(connState, msg.header.requestID, email);
    if (!success) {
      return;
    }

    // Authentication successful
    connState.authState.authenticated = true;
    connState.authState.principalName = result.subject;
    connState.authState.email = email;
    connState.authState.tokenExp = result.exp;
    connState.socket.write(this.messageBuilder.buildAuthSuccessResponse(
      msg.header.requestID,
      connState.authState.conversationId
    ));
    this.emit('authSuccess', connState.id, `${result.subject} (${email}) (via saslContinue)`);
  }

  private async provisionUser(connState: ConnectionState, requestId: number, email: string): Promise<boolean> {
    this.emit('debug', connState.id, `Checking roles for ${email}...`);
    const adminDb = this.backendClient.db('admin');

    // Verify role exists
    const rolesInfo = await adminDb.command({ rolesInfo: email });
    if (!rolesInfo.roles || rolesInfo.roles.length === 0) {
      this.emit('debug', connState.id, `Role ${email} not found`);
      connState.socket.write(this.messageBuilder.buildAuthFailureResponse(
        requestId,
        `Role '${email}' not defined in MongoDB`
      ));
      return false;
    }

    // Create/Update user with random password
    const password = crypto.randomBytes(32).toString('base64');

    try {
      await adminDb.command({
        updateUser: email,
        pwd: password,
        roles: [{ role: email, db: 'admin' }]
      });
      this.emit('debug', connState.id, `Updated user ${email}`);
    } catch (err: any) {
      if (err.code === 11) { // UserNotFound
        await adminDb.command({
          createUser: email,
          pwd: password,
          roles: [{ role: email, db: 'admin' }]
        });
        this.emit('debug', connState.id, `Created user ${email}`);
      } else {
        throw err;
      }
    }

    // Create dedicated connection for this user
    const { protocol, host, params } = this.backendInfo;
    const userClient = new MongoClient(
      `${protocol}//${encodeURIComponent(email)}:${encodeURIComponent(password)}@${host}/?${params.toString()}`
    );
    await userClient.connect();
    connState.userClient = userClient;

    return true;
  }

  private extractJwtFromPayload(connId: number, payload?: Uint8Array): string | null {
    if (!payload || payload.length === 0) {
      this.emit('debug', connId, 'saslStart with empty payload');
      return null;
    }

    this.emit('debug', connId, `saslStart payload size: ${payload.length} bytes`);

    let payloadDoc: Record<string, unknown>;
    try {
      payloadDoc = deserialize(payload);
    } catch (err) {
      this.emit('debug', connId, `saslStart payload parse error: ${err}`);
      return null;
    }

    const jwt = payloadDoc.jwt as string | undefined;
    if (!jwt) {
      this.emit('debug', connId, 'saslStart payload has no jwt field');
      return null;
    }

    // Log JWT payload for debugging
    try {
      const parts = jwt.split('.');
      if (parts.length === 3) {
        this.emit('debug', connId, `JWT payload: ${Buffer.from(parts[1], 'base64').toString('utf8')}`);
      }
    } catch { /* ignore */ }

    return jwt;
  }

  private async handleHello(connState: ConnectionState, msg: FullMessage): Promise<void> {
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
    connState.socket.write(response);
  }

  private sendReauthRequired(connState: ConnectionState, requestID: number, reason: string): void {
    connState.authState.authenticated = false;
    connState.authState.tokenExp = undefined;
    connState.socket.write(this.messageBuilder.buildErrorResponse(
      requestID,
      `Reauthentication required: ${reason}`,
      391,
      'ReauthenticationRequired'
    ));
    this.emit('reauthRequired', connState.id, reason);
  }

  private async forwardCommand(connState: ConnectionState, msg: FullMessage): Promise<void> {
    const dbName = getCommandDb(msg) || 'admin';
    const body = getCommandBody(msg);

    if (!body) {
      const response = this.messageBuilder.buildErrorResponse(
        msg.header.requestID,
        'Invalid command format'
      );
      connState.socket.write(response);
      return;
    }

    // Check if token has expired - return ReauthenticationRequired (code 391) if so
    // This allows compliant drivers to reauthenticate without dropping the connection
    const tokenExp = connState.authState.tokenExp;
    if (tokenExp && Math.floor(Date.now() / 1000) >= tokenExp) {
      const cmdName = Object.keys(body).find(k => !k.startsWith('$')) || 'unknown';
      this.sendReauthRequired(connState, msg.header.requestID, `command ${cmdName} - token expired`);
      return;
    }

    try {
      const command = { ...body };
      delete command.$db;

      // Use the dedicated user client
      const result = await connState.userClient!.db(dbName).command(command as Document);

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
      connState.socket.write(response);

      this.emit('commandForwarded', connState.id, dbName, Object.keys(command)[0]);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      const response = this.messageBuilder.buildErrorResponse(
        msg.header.requestID,
        errorMessage
      );
      connState.socket.write(response);
      this.emit('commandError', connState.id, errorMessage);
    }
  }
}
