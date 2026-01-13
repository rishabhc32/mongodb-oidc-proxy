import net from 'net';
import { EventEmitter } from 'events';
import { MongoClient, Document } from 'mongodb';
import { deserialize, Long } from 'bson';
import { WireProtocolParser } from '../parse-stream';
import { FullMessage, getSaslCommand, getCommandDb, getCommandBody } from '../parse';
import { JWTValidator } from './jwt-validator';
import { MessageBuilder } from './message-builder';
import type { OIDCProxyConfig, OIDCAuthState, IdpInfo } from './types';

interface ConnectionState {
  id: number;
  socket: net.Socket;
  parser: WireProtocolParser;
  authState: OIDCAuthState;
  buffer: Buffer[];
}

export class OIDCProxy extends EventEmitter {
  private server: net.Server;
  private backendClient: MongoClient;
  private jwtValidator: JWTValidator;
  private messageBuilder: MessageBuilder;
  private config: OIDCProxyConfig;
  private connections: Map<number, ConnectionState> = new Map();
  private connectionIdCounter = 0;
  private conversationIdCounter = 0;

  constructor(config: OIDCProxyConfig) {
    super();
    this.config = config;
    this.jwtValidator = new JWTValidator(config.issuer, config.clientId, config.jwksUri, config.audience);
    this.messageBuilder = new MessageBuilder();
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
    const parser = new WireProtocolParser();

    const connState: ConnectionState = {
      id: connId,
      socket,
      parser,
      authState: {
        conversationId: 0,
        authenticated: false
      },
      buffer: []
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

    socket.on('close', () => {
      this.connections.delete(connId);
      this.emit('connectionClosed', connId);
    });

    socket.on('error', (err: Error) => {
      this.emit('connectionError', connId, err);
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
      await this.handleSaslContinue(connState, msg, saslCmd.payload);
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

    // Check if client sent JWT in saslStart payload (cached token from previous auth)
    if (payload && payload.length > 0) {
      this.emit('debug', connState.id, `saslStart payload size: ${payload.length} bytes`);
      try {
        const payloadDoc = deserialize(payload);
        const payloadKeys = Object.keys(payloadDoc);
        this.emit('debug', connState.id, `saslStart payload keys: ${payloadKeys.join(', ')}`);

        const jwt = payloadDoc.jwt;
        if (jwt) {
          // Decode JWT payload for debugging (middle part between dots)
          try {
            const parts = jwt.split('.');
            if (parts.length === 3) {
              const payloadB64 = parts[1];
              const payloadJson = Buffer.from(payloadB64, 'base64').toString('utf8');
              this.emit('debug', connState.id, `JWT payload: ${payloadJson}`);
            }
          } catch { /* ignore decode errors */ }

          this.emit('debug', connState.id, 'saslStart has JWT, validating...');
          // Validate the JWT
          const result = await this.jwtValidator.validate(jwt);
          if (result.valid) {
            // Authentication successful via saslStart
            connState.authState.authenticated = true;
            connState.authState.principalName = result.subject;
            const response = this.messageBuilder.buildAuthSuccessResponse(
              msg.header.requestID,
              connState.authState.conversationId
            );
            connState.socket.write(response);
            this.emit('authSuccess', connState.id, result.subject + ' (via saslStart)');
            return;
          } else {
            this.emit('debug', connState.id, `JWT validation failed: ${result.error}`);
          }
        } else {
          this.emit('debug', connState.id, 'saslStart payload has no jwt field');
        }
      } catch (err) {
        this.emit('debug', connState.id, `saslStart payload parse error: ${err}`);
      }
    } else {
      this.emit('debug', connState.id, 'saslStart with empty payload');
    }

    // No JWT or validation failed - return IdP info for OIDC flow
    const idpInfo: IdpInfo = {
      issuer: this.config.issuer,
      clientId: this.config.clientId
    };

    const response = this.messageBuilder.buildSaslStartResponse(
      msg.header.requestID,
      connState.authState.conversationId,
      idpInfo
    );

    connState.socket.write(response);
    this.emit('saslStart', connState.id, idpInfo);
  }

  private async handleSaslContinue(
    connState: ConnectionState,
    msg: FullMessage,
    payload?: Uint8Array
  ): Promise<void> {
    if (!payload || payload.length === 0) {
      const response = this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        'Missing JWT payload'
      );
      connState.socket.write(response);
      return;
    }

    // Parse the payload BSON to extract JWT
    let jwt: string;
    try {
      const payloadDoc = deserialize(payload);
      jwt = payloadDoc.jwt;
      if (!jwt) {
        throw new Error('No jwt field in payload');
      }
    } catch (err) {
      const response = this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        'Invalid payload format'
      );
      connState.socket.write(response);
      return;
    }

    // Decode JWT payload for debugging
    try {
      const parts = jwt.split('.');
      if (parts.length === 3) {
        const payloadB64 = parts[1];
        const payloadJson = Buffer.from(payloadB64, 'base64').toString('utf8');
        this.emit('debug', connState.id, `saslContinue JWT payload: ${payloadJson}`);
      }
    } catch { /* ignore decode errors */ }

    // Validate JWT
    const result = await this.jwtValidator.validate(jwt);

    if (!result.valid) {
      const response = this.messageBuilder.buildAuthFailureResponse(
        msg.header.requestID,
        `Authentication failed: ${result.error}`
      );
      connState.socket.write(response);
      this.emit('authFailed', connState.id, result.error);
      return;
    }

    // Authentication successful
    connState.authState.authenticated = true;
    connState.authState.principalName = result.subject;

    const response = this.messageBuilder.buildAuthSuccessResponse(
      msg.header.requestID,
      connState.authState.conversationId
    );
    connState.socket.write(response);
    this.emit('authSuccess', connState.id, result.subject);
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

    try {
      // Remove $db field as we specify db via the driver
      const command = { ...body };
      delete command.$db;

      const db = this.backendClient.db(dbName);
      const result = await db.command(command as Document);

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
