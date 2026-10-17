import { Proxy, ConnectionPair } from '@src/proxy';
import { OIDCProxy, OIDCConnection } from '@src/oidc';
import type { FullMessage } from '@src/parse';
import { EJSON } from 'bson';
import fs from 'fs';
import os from 'os';
import winston from 'winston';

type OptionalUser = string | null | undefined;

export interface ParsedArgs {
  help: boolean;
  ndjson: boolean;
  oidcMode: boolean;
  logLevel: 'debug' | 'info';
  tags: string[];
  issuer?: string;
  clientId?: string;
  connectionString?: string;
  jwksUri?: string;
  audience?: string;
  logFile?: string;
  maxConnectionsPerUser?: number;
  positional: string[];
}

export function parseArgs(argv: string[]): ParsedArgs {
  const args: ParsedArgs = {
    help: false,
    ndjson: false,
    oidcMode: false,
    logLevel: 'info',
    tags: [],
    positional: []
  };

  let i = 2; // Skip node and script path
  while (i < argv.length) {
    const arg = argv[i];

    if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else if (arg === '--ndjson') {
      args.ndjson = true;
    } else if (arg === '--oidc-mode') {
      args.oidcMode = true;
    } else if (arg === '--log-level' && i + 1 < argv.length) {
      const level = argv[++i];
      if (level === 'debug' || level === 'info') {
        args.logLevel = level;
      }
    } else if (arg === '--tag' && i + 1 < argv.length) {
      args.tags.push(argv[++i]);
    } else if (arg === '--issuer' && i + 1 < argv.length) {
      args.issuer = argv[++i];
    } else if (arg === '--client-id' && i + 1 < argv.length) {
      args.clientId = argv[++i];
    } else if (arg === '--connection-string' && i + 1 < argv.length) {
      args.connectionString = argv[++i];
    } else if (arg === '--jwks-uri' && i + 1 < argv.length) {
      args.jwksUri = argv[++i];
    } else if (arg === '--audience' && i + 1 < argv.length) {
      args.audience = argv[++i];
    } else if (arg === '--log-file' && i + 1 < argv.length) {
      args.logFile = argv[++i];
    } else if (arg === '--max-connections-per-user' && i + 1 < argv.length) {
      const n = Number(argv[++i]);
      args.maxConnectionsPerUser = Number.isInteger(n) && n > 0 ? n : undefined;
    } else if (!arg.startsWith('--')) {
      args.positional.push(arg);
    }

    i++;
  }

  return args;
}

// Passwords in createUser/updateUser commands must never reach the logs
export function redactPasswords(request: unknown): unknown {
  if (request && typeof request === 'object' && 'pwd' in request) {
    return { ...request, pwd: '[REDACTED]' };
  }
  return request;
}

// Precedence: --connection-string, MONGO_CONNECTION_STRING, then the file named by
// MONGO_CONNECTION_STRING_FILE (how Docker and Kubernetes mount secrets)
export function resolveConnectionString(args: ParsedArgs, env: NodeJS.ProcessEnv): string | undefined {
  if (args.connectionString) {
    return args.connectionString;
  }
  if (env.MONGO_CONNECTION_STRING) {
    return env.MONGO_CONNECTION_STRING;
  }
  if (env.MONGO_CONNECTION_STRING_FILE) {
    return fs.readFileSync(env.MONGO_CONNECTION_STRING_FILE, 'utf8').trim() || undefined;
  }
  return undefined;
}

export function parseAddress(str: string): { host: string; port: number } | { path: string } {
  if (str.startsWith('/') || str.includes('\\')) {
    return { path: str };
  }
  const [host, port] = str.split(':');
  if (port === undefined) {
    return { host: 'localhost', port: +host };
  }
  return { host, port: +port };
}

function printUsage(): void {
  console.log(`usage: mongodb-wp-proxy [options] <args>

Transparent proxy mode (default):
  mongodb-wp-proxy [--ndjson] <remotehost:remoteport> <[localhost:]localport>

OIDC termination mode:
  mongodb-wp-proxy --oidc-mode [options] <[localhost:]localport>

Options:
  --help, -h            Show this help message and exit
  --ndjson              Output in newline-delimited JSON format
  --log-level <level>   Log level: 'debug' or 'info' (default: info)
  --tag <value>         Optional tag included in JSON log entries
  --oidc-mode           Enable OIDC authentication termination mode
  --issuer <url>        OIDC issuer URL (required for OIDC mode)
  --client-id <id>      OAuth client ID to return to clients (required for OIDC mode)
  --connection-string <uri>  Backend MongoDB connection string (or MONGO_CONNECTION_STRING env,
                        or MONGO_CONNECTION_STRING_FILE naming a file that contains it)
  --jwks-uri <url>      Custom JWKS endpoint (optional, defaults to issuer/.well-known/jwks.json)
  --audience <aud>      Expected JWT audience claim (optional)
  --log-file <path>     Write NDJSON logs to a rotating file instead of stdout
  --max-connections-per-user <n>  Max concurrent connections per user (default: unlimited)
`);
}

function formatLogPrefix(connId: string, user?: OptionalUser, tags?: string[]): string {
  const tagStr = tags && tags.length > 0 ? ` [${tags.join(',')}]` : '';
  return `[${connId}]${user ? ` [${user}]` : ''}${tagStr}`;
}

function utcnow(): string {
  return new Date().toISOString();
}

export interface LogSink {
  // Writes an event as one NDJSON line
  writeEvent: (ev: string, fields: Record<string, unknown>) => void;
  // Resolves once every line written so far has reached the file or stdout
  closeLog: () => Promise<void>;
}

export function createLogSink(logFile: string | undefined, tags: string[]): LogSink {
  function format(ev: string, fields: Record<string, unknown>): string {
    return EJSON.stringify({ ts: utcnow(), ev, ...fields, tags });
  }

  if (!logFile) {
    return {
      writeEvent: (ev, fields) => console.log(format(ev, fields)),
      closeLog: () => new Promise<void>((resolve) => process.stdout.write('', () => resolve()))
    };
  }
  const logger = winston.createLogger({
    level: 'info',
    format: winston.format.printf(({ message }) => message as string),
    transports: [
      new winston.transports.File({
        filename: logFile,
        maxsize: 50 * 1024 * 1024, // 50MB
        maxFiles: 100,
        tailable: true
      })
    ]
  });
  return {
    writeEvent: (ev, fields) => logger.info(format(ev, fields)),
    // 'finish' is emitted once the ended logger has flushed to its transports
    closeLog: () =>
      new Promise<void>((resolve) => {
        logger.once('finish', () => resolve());
        logger.end();
      })
  };
}

// `docker stop` sends SIGTERM, then SIGKILL 10 seconds later. Node runs as PID 1 in
// the image, and PID 1 ignores signals it has no handler for, so without this the
// proxy would be killed with requests in flight and log lines unwritten
function shutdownOnSignal(shutdown: () => Promise<void>): void {
  let shuttingDown = false;
  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.on(signal, () => {
      if (shuttingDown) {
        // A second signal skips the graceful shutdown
        process.exit(128 + os.constants.signals[signal]);
      }
      shuttingDown = true;
      console.error(`Received ${signal}, shutting down`);
      shutdown()
        .then(() => process.exit(0))
        .catch((err: Error) => {
          console.error(`Error during shutdown: ${err.message}`);
          process.exit(1);
        });
    });
  }
}

async function runTransparentProxy(args: ParsedArgs): Promise<void> {
  const targetStr = args.positional[0];
  const localStr = args.positional[1];

  if (!targetStr || !localStr) {
    printUsage();
    return;
  }

  const target = parseAddress(targetStr);
  const local = parseAddress(localStr);
  const { writeEvent, closeLog } = createLogSink(args.logFile, args.tags);

  const proxy = new Proxy(target);
  shutdownOnSignal(async () => {
    await proxy.close().catch(() => {}); // Rejects if the signal came before listening
    await closeLog();
  });

  proxy.on('newConnection', (conn: ConnectionPair) => {
    const { connId } = conn;
    if (args.ndjson) {
      writeEvent('newConnection', { connId, bytesInTotal: 0, bytesOutTotal: 0 });
    } else {
      console.log(`[${connId} outgoing] New connection from ${conn.incoming}`);
    }

    conn.on('connectionClosed', (source: string) => {
      if (args.ndjson) {
        writeEvent('connectionClosed', { connId, source, bytesInTotal: conn.bytesIn, bytesOutTotal: conn.bytesOut });
      } else {
        console.log(`[${connId} ${source}] Connection closed`);
      }
    });

    conn.on('connectionError', (source: string, err: Error) => {
      if (args.ndjson) {
        writeEvent('connectionError', { connId, source, error: err.message });
      } else {
        console.log(`[${connId} ${source}] Connection error: ${err.message}`);
      }
    });

    conn.on('message', (source: string, msg: FullMessage) => {
      if (args.ndjson) {
        const messageBytes = msg.header?.messageLength ?? 0;
        writeEvent('commandForwarded', {
          connId,
          source,
          msg,
          requestBytes: source === 'outgoing' ? messageBytes : 0,
          responseBytes: source === 'incoming' ? messageBytes : 0,
          bytesInTotal: conn.bytesIn,
          bytesOutTotal: conn.bytesOut
        });
      } else {
        console.log(`[${connId} ${source}] Message received`);
        console.dir(msg.contents, { depth: Infinity, customInspect: true });
      }
    });

    conn.on('parseError', (source: string, err: Error) => {
      if (args.ndjson) {
        writeEvent('parseError', { connId, source, error: err.message });
      } else {
        console.log(`[${connId} ${source}] Failed to parse message: ${err.message}`);
      }
    });
  });

  await proxy.listen(local);
  if (args.ndjson) {
    writeEvent('listening', { addr: proxy.address(), local, target });
  } else {
    console.log('Listening on', proxy.address(), 'forwarding', local, 'to', target);
  }
}

async function runOIDCProxy(args: ParsedArgs): Promise<void> {
  try {
    args.connectionString = resolveConnectionString(args, process.env);
  } catch (err) {
    console.error(`Error: cannot read MONGO_CONNECTION_STRING_FILE: ${(err as Error).message}`);
    process.exit(1);
  }

  if (!args.issuer || !args.clientId || !args.connectionString) {
    console.error(
      'Error: --oidc-mode requires --issuer, --client-id, and --connection-string (or MONGO_CONNECTION_STRING / MONGO_CONNECTION_STRING_FILE env)'
    );
    printUsage();
    process.exit(1);
  }

  const localStr = args.positional[0];
  if (!localStr) {
    console.error('Error: Missing listen address');
    printUsage();
    process.exit(1);
  }

  const local = parseAddress(localStr);
  if ('path' in local) {
    console.error('Error: Unix socket not supported for OIDC mode');
    process.exit(1);
  }

  const { writeEvent, closeLog } = createLogSink(args.logFile, args.tags);

  const proxy = new OIDCProxy({
    issuer: args.issuer,
    clientId: args.clientId,
    connectionString: args.connectionString,
    jwksUri: args.jwksUri,
    audience: args.audience,
    listenPort: local.port,
    listenHost: local.host,
    maxConnectionsPerUser: args.maxConnectionsPerUser
  });

  proxy.on('listening', (addr) => {
    if (args.ndjson) {
      writeEvent('listening', { addr, mode: 'oidc', issuer: args.issuer });
    } else {
      console.log(`OIDC Proxy listening on ${addr.address}:${addr.port}`);
      console.log(`  Issuer: ${args.issuer}`);
      console.log(`  Client ID: ${args.clientId}`);
    }
  });

  proxy.on('backendConnected', () => {
    if (args.ndjson) {
      writeEvent('backendConnected', {});
    } else {
      console.log('Connected to backend MongoDB');
    }
  });

  proxy.on('newConnection', (conn: OIDCConnection) => {
    const { connId } = conn;
    // Prefix of text lines about a user's actions
    const prefix = (user: OptionalUser) => formatLogPrefix(connId, user, args.tags);

    if (args.ndjson) {
      writeEvent('newConnection', { connId, bytesInTotal: 0, bytesOutTotal: 0 });
    } else {
      console.log(`[${connId}] New connection from ${conn.incoming}`);
    }

    conn.on('connectionClosed', () => {
      if (args.ndjson) {
        writeEvent('connectionClosed', {
          connId,
          user: conn.getUser() ?? null,
          bytesInTotal: conn.bytesIn,
          bytesOutTotal: conn.bytesOut
        });
      } else {
        console.log(`[${connId}] Connection closed (in: ${conn.bytesIn} bytes, out: ${conn.bytesOut} bytes)`);
      }
    });

    conn.on('connectionError', (err: Error) => {
      if (args.ndjson) {
        writeEvent('connectionError', { connId, err: err.message });
      } else {
        console.log(`[${connId}] Connection error: ${err.message}`);
      }
    });

    conn.on('saslStart', () => {
      if (args.ndjson) {
        writeEvent('saslStart', { connId });
      } else {
        console.log(`[${connId}] SASL start - returning IdP info`);
      }
    });

    conn.on('authAttempt', (user: OptionalUser, jwt: Record<string, unknown> | null) => {
      if (args.ndjson) {
        writeEvent('authAttempt', { connId, user: user ?? null, jwt });
      } else {
        console.log(`${prefix(user)} Attempting JWT authentication: ${JSON.stringify(jwt)}`);
      }
    });

    conn.on('authSuccess', (user: string, subject?: string) => {
      if (args.ndjson) {
        writeEvent('authSuccess', { connId, user: user ?? null, subject: subject ?? null });
      } else {
        console.log(`${prefix(user)} Authentication successful for: ${subject ?? null}`);
      }
    });

    conn.on('authFailed', (user: OptionalUser, error: string) => {
      if (args.ndjson) {
        writeEvent('authFailed', { connId, user: user ?? null, error });
      } else {
        console.log(`${prefix(user)} Authentication failed: ${error}`);
      }
    });

    conn.on(
      'commandForwarded',
      (user: string, db: string, cmd: string, request: any, response: any, requestBytes = 0, responseBytes = 0) => {
        if (args.ndjson) {
          const fields: Record<string, unknown> = {
            connId,
            user: user ?? null,
            db,
            cmd,
            request: redactPasswords(request),
            requestBytes,
            responseBytes,
            bytesInTotal: conn.bytesIn,
            bytesOutTotal: conn.bytesOut
          };
          if (args.logLevel === 'debug') {
            fields.response = response;
          }
          writeEvent('commandForwarded', fields);
        } else {
          console.log(`${prefix(user)} Forwarded command: ${db}.${cmd}`);
        }
      }
    );

    conn.on('commandError', (user: string, error: string, db?: string, cmd?: string, request?: any) => {
      if (args.ndjson) {
        writeEvent('commandError', {
          connId,
          user: user ?? null,
          db,
          cmd,
          request: redactPasswords(request),
          error,
          bytesInTotal: conn.bytesIn,
          bytesOutTotal: conn.bytesOut
        });
      } else {
        console.log(`${prefix(user)} Command error: ${error}`);
      }
    });

    conn.on('parseError', (err: Error) => {
      if (args.ndjson) {
        writeEvent('parseError', { connId, err: err.message });
      } else {
        console.log(`[${connId}] Parse error: ${err.message}`);
      }
    });

    conn.on('authRequired', (cmdName: string | null) => {
      if (args.ndjson) {
        writeEvent('authRequired', { connId, cmdName });
      } else {
        console.log(`[${connId}] Auth required for command: ${cmdName || 'unknown'}`);
      }
    });

    conn.on('debug', (user: OptionalUser, message: string) => {
      if (args.logLevel !== 'debug') {
        return;
      }
      if (args.ndjson) {
        writeEvent('debug', { connId, user: user ?? null, message });
      } else {
        console.log(`${prefix(user)} DEBUG: ${message}`);
      }
    });

    conn.on('connectionTimeout', () => {
      if (args.ndjson) {
        writeEvent('connectionTimeout', { connId, user: conn.getUser() ?? null });
      } else {
        console.log(`[${connId}] Connection timed out`);
      }
    });

    conn.on('reauthRequired', (user: OptionalUser, reason: string) => {
      if (args.ndjson) {
        writeEvent('reauthRequired', { connId, user: user ?? null, reason });
      } else {
        console.log(`${prefix(user)} Reauthentication required: ${reason}`);
      }
    });
  });

  let started = false;
  shutdownOnSignal(async () => {
    // Before startup completes there is nothing to drain
    if (started) {
      await proxy.stop();
    }
    await closeLog();
  });

  await proxy.start();
  started = true;
}

export async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  if (args.help || (args.positional.length === 0 && !args.oidcMode)) {
    printUsage();
    return;
  }

  if (args.oidcMode) {
    await runOIDCProxy(args);
  } else {
    await runTransparentProxy(args);
  }
}

if (require.main === module) {
  main().catch((err: Error) =>
    process.nextTick(() => {
      throw err;
    })
  );
}
