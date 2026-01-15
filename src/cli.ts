import { Proxy, ConnectionPair } from '@src/proxy';
import { OIDCProxy, OIDCProxyConfig, OIDCConnection } from '@src/oidc';
import type { FullMessage } from '@src/parse';
import { EJSON } from 'bson';

type OptionalUser = string | null | undefined;

export interface ParsedArgs {
  help: boolean;
  ndjson: boolean;
  oidcMode: boolean;
  logLevel: 'debug' | 'info';
  issuer?: string;
  clientId?: string;
  connectionString?: string;
  jwksUri?: string;
  audience?: string;
  positional: string[];
}

export function parseArgs (argv: string[]): ParsedArgs {
  const args: ParsedArgs = {
    help: false,
    ndjson: false,
    oidcMode: false,
    logLevel: 'info',
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
    } else if (!arg.startsWith('--')) {
      args.positional.push(arg);
    }

    i++;
  }

  return args;
}

export function parseAddress (str: string): { host: string; port: number } | { path: string } {
  if (str.startsWith('/') || str.includes('\\')) {
    return { path: str };
  }
  const [host, port] = str.split(':');
  if (port === undefined) {
    return { host: 'localhost', port: +host };
  }
  return { host, port: +port };
}

function printUsage (): void {
  console.log(`usage: mongodb-wp-proxy [options] <args>

Transparent proxy mode (default):
  mongodb-wp-proxy [--ndjson] <remotehost:remoteport> <[localhost:]localport>

OIDC termination mode:
  mongodb-wp-proxy --oidc-mode [options] <[localhost:]localport>

Options:
  --help, -h            Show this help message and exit
  --ndjson              Output in newline-delimited JSON format
  --log-level <level>   Log level: 'debug' or 'info' (default: info)
  --oidc-mode           Enable OIDC authentication termination mode
  --issuer <url>        OIDC issuer URL (required for OIDC mode)
  --client-id <id>      OAuth client ID to return to clients (required for OIDC mode)
  --connection-string <uri>  Backend MongoDB connection string (required for OIDC mode)
  --jwks-uri <url>      Custom JWKS endpoint (optional, defaults to issuer/.well-known/jwks.json)
  --audience <aud>      Expected JWT audience claim (optional)
`);
}

function normalizeUser (user: OptionalUser): string | null {
  return user ?? null;
}

function formatLogPrefix (connId: number, user?: OptionalUser): string {
  return `[${connId}]${user ? ` [${user}]` : ''}`;
}

function utcnow (): string {
  return new Date().toISOString();
}

async function runTransparentProxy (args: ParsedArgs): Promise<void> {
  const targetStr = args.positional[0];
  const localStr = args.positional[1];

  if (!targetStr || !localStr) {
    printUsage();
    return;
  }

  const target = parseAddress(targetStr);
  const local = parseAddress(localStr);

  const proxy = new Proxy(target);

  proxy.on('newConnection', (conn: ConnectionPair) => {
    if (args.ndjson) {
      console.log(JSON.stringify({
        ts: utcnow(),
        ev: 'newConnection',
        conn,
        bytes_in_total: 0,
        bytes_out_total: 0
      }));
    } else {
      console.log(`[${conn.connId} outgoing] New connection from ${conn.incoming}`);
    }

    conn.on('connectionClosed', (source: string) => {
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'connectionClosed',
          conn,
          source,
          bytes_in_total: conn.bytesIn,
          bytes_out_total: conn.bytesOut
        }));
      } else {
        console.log(`[${conn.connId} ${source}] Connection closed`);
      }
    });

    conn.on('connectionError', (source: string, err: Error) => {
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'connectionError',
          conn,
          source,
          err: err.message
        }));
      } else {
        console.log(`[${conn.connId} ${source}] Connection error: ${err.message}`);
      }
    });

    conn.on('message', (source: string, msg: FullMessage) => {
      if (args.ndjson) {
        console.log(EJSON.stringify({
          ts: utcnow(),
          ev: 'message',
          conn: conn.toJSON(),
          source,
          msg,
          bytes_in_total: conn.bytesIn,
          bytes_out_total: conn.bytesOut
        }));
      } else {
        console.log(`[${conn.connId} ${source}] Message received`);
        console.dir(msg.contents, { depth: Infinity, customInspect: true });
      }
    });

    conn.on('parseError', (source: string, err: Error) => {
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'parseError',
          conn,
          source,
          err: err.message
        }));
      } else {
        console.log(`[${conn.connId} ${source}] Failed to parse message: ${err.message}`);
      }
    });
  });

  await proxy.listen(local);
  if (args.ndjson) {
    console.log(JSON.stringify({
      ts: utcnow(),
      ev: 'listening',
      addr: proxy.address(),
      local,
      target
    }));
  } else {
    console.log('Listening on', proxy.address(), 'forwarding', local, 'to', target);
  }
}

async function runOIDCProxy (args: ParsedArgs): Promise<void> {
  if (!args.issuer || !args.clientId || !args.connectionString) {
    console.error('Error: --oidc-mode requires --issuer, --client-id, and --connection-string');
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

  const config: OIDCProxyConfig = {
    issuer: args.issuer,
    clientId: args.clientId,
    connectionString: args.connectionString,
    jwksUri: args.jwksUri,
    audience: args.audience,
    listenPort: local.port,
    listenHost: local.host
  };

  const proxy = new OIDCProxy(config);

  proxy.on('listening', (addr) => {
    if (args.ndjson) {
      console.log(JSON.stringify({
        ts: utcnow(),
        ev: 'listening',
        addr,
        mode: 'oidc',
        issuer: config.issuer
      }));
    } else {
      console.log(`OIDC Proxy listening on ${addr.address}:${addr.port}`);
      console.log(`  Issuer: ${config.issuer}`);
      console.log(`  Client ID: ${config.clientId}`);
    }
  });

  proxy.on('backendConnected', () => {
    if (args.ndjson) {
      console.log(JSON.stringify({
        ts: utcnow(),
        ev: 'backendConnected'
      }));
    } else {
      console.log('Connected to backend MongoDB');
    }
  });

  proxy.on('newConnection', (conn: OIDCConnection) => {
    if (args.ndjson) {
      console.log(JSON.stringify({
        ts: utcnow(),
        ev: 'newConnection',
        conn: conn.toJSON(),
        bytes_in_total: 0,
        bytes_out_total: 0
      }));
    } else {
      console.log(`[${conn.connId}] New connection from ${conn.incoming}`);
    }

    conn.on('connectionClosed', () => {
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'connectionClosed',
          connId: conn.connId,
          bytes_in_total: conn.bytesIn,
          bytes_out_total: conn.bytesOut
        }));
      } else {
        console.log(`[${conn.connId}] Connection closed (in: ${conn.bytesIn} bytes, out: ${conn.bytesOut} bytes)`);
      }
    });

    conn.on('connectionError', (err: Error) => {
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'connectionError',
          connId: conn.connId,
          err: err.message
        }));
      } else {
        console.log(`[${conn.connId}] Connection error: ${err.message}`);
      }
    });

    conn.on('saslStart', () => {
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'saslStart',
          connId: conn.connId
        }));
      } else {
        console.log(`[${conn.connId}] SASL start - returning IdP info`);
      }
    });

    conn.on('authAttempt', (user: OptionalUser, jwt: Record<string, unknown> | null) => {
      const normalizedUser = normalizeUser(user);
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'authAttempt',
          connId: conn.connId,
          user: normalizedUser,
          jwt
        }));
      } else {
        console.log(`${formatLogPrefix(conn.connId, normalizedUser)} Attempting JWT authentication: ${JSON.stringify(jwt)}`);
      }
    });

    conn.on('authSuccess', (user: string, subject?: string) => {
      const normalizedUser = normalizeUser(user);
      const normalizedSubject = normalizeUser(subject);
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'authSuccess',
          connId: conn.connId,
          user: normalizedUser,
          subject: normalizedSubject
        }));
      } else {
        console.log(`[${conn.connId}] [${normalizedUser}] Authentication successful for: ${normalizedSubject}`);
      }
    });

    conn.on('authFailed', (user: OptionalUser, error: string) => {
      const normalizedUser = normalizeUser(user);
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'authFailed',
          connId: conn.connId,
          user: normalizedUser,
          error
        }));
      } else {
        console.log(`${formatLogPrefix(conn.connId, normalizedUser)} Authentication failed: ${error}`);
      }
    });

    conn.on('commandForwarded', (user: string, db: string, cmd: string, request: any, response: any) => {
      const normalizedUser = normalizeUser(user);
      if (args.ndjson) {
        console.log(EJSON.stringify({
          ts: utcnow(),
          ev: 'commandForwarded',
          connId: conn.connId,
          user: normalizedUser,
          db,
          cmd,
          request,
          response,
          bytes_in_total: conn.bytesIn,
          bytes_out_total: conn.bytesOut
        }));
      } else {
        console.log(`[${conn.connId}] [${normalizedUser}] Forwarded command: ${db}.${cmd}`);
      }
    });

    conn.on('commandError', (user: string, error: string) => {
      const normalizedUser = normalizeUser(user);
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'commandError',
          connId: conn.connId,
          user: normalizedUser,
          error,
          bytes_in_total: conn.bytesIn,
          bytes_out_total: conn.bytesOut
        }));
      } else {
        console.log(`[${conn.connId}] [${normalizedUser}] Command error: ${error}`);
      }
    });

    conn.on('parseError', (err: Error) => {
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'parseError',
          connId: conn.connId,
          err: err.message
        }));
      } else {
        console.log(`[${conn.connId}] Parse error: ${err.message}`);
      }
    });

    conn.on('authRequired', (cmdName: string | null) => {
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'authRequired',
          connId: conn.connId,
          cmdName
        }));
      } else {
        console.log(`[${conn.connId}] Auth required for command: ${cmdName || 'unknown'}`);
      }
    });

    conn.on('debug', (user: OptionalUser, message: string) => {
      if (args.logLevel !== 'debug') {
        return;
      }
      const normalizedUser = normalizeUser(user);
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'debug',
          connId: conn.connId,
          user: normalizedUser,
          message
        }));
      } else {
        console.log(`${formatLogPrefix(conn.connId, normalizedUser)} DEBUG: ${message}`);
      }
    });

    conn.on('connectionTimeout', () => {
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'connectionTimeout',
          connId: conn.connId
        }));
      } else {
        console.log(`[${conn.connId}] Connection timed out`);
      }
    });

    conn.on('reauthRequired', (user: OptionalUser, reason: string) => {
      const normalizedUser = normalizeUser(user);
      if (args.ndjson) {
        console.log(JSON.stringify({
          ts: utcnow(),
          ev: 'reauthRequired',
          connId: conn.connId,
          user: normalizedUser,
          reason
        }));
      } else {
        console.log(`${formatLogPrefix(conn.connId, normalizedUser)} Reauthentication required: ${reason}`);
      }
    });
  });

  await proxy.start();
}

if (require.main === module) {
  (async () => {
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
  })().catch((err: Error) => process.nextTick(() => { throw err; }));
}
