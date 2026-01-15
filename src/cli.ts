import { Proxy, ConnectionPair } from '@src/proxy';
import { OIDCProxy, OIDCProxyConfig } from '@src/oidc';
import type { FullMessage } from '@src/parse';
import { EJSON } from 'bson';

type OptionalUser = string | null | undefined;

interface ParsedArgs {
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

function parseArgs (argv: string[]): ParsedArgs {
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

function parseAddress (str: string): { host: string; port: number } | { path: string } {
  if (str.startsWith('/') || str.includes('\\')) {
    return { path: str };
  }
  const [host, port] = str.split(':');
  if (port === undefined) {
    return { host: 'localhost', port: +host };
  }
  return { host, port: +port };
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
      console.log(JSON.stringify({ ts: utcnow(), ev: 'newConnection', conn }));
    } else {
      console.log(`[${conn.id} outgoing] New connection from ${conn.incoming}`);
    }

    conn.on('connectionEnded', (source: string) => {
      if (args.ndjson) {
        console.log(JSON.stringify({ ts: utcnow(), ev: 'connectionEnded', conn, source }));
      } else {
        console.log(`[${conn.id} ${source}] Connection closed`);
      }
    });

    conn.on('connectionError', (source: string, err: Error) => {
      if (args.ndjson) {
        console.log(JSON.stringify({ ts: utcnow(), ev: 'connectionError', conn, source, err: err.message }));
      } else {
        console.log(`[${conn.id} ${source}] Connection error: ${err.message}`);
      }
    });

    conn.on('message', (source: string, msg: FullMessage) => {
      if (args.ndjson) {
        console.log(EJSON.stringify({ ts: utcnow(), ev: 'message', conn: conn.toJSON(), source, msg }));
      } else {
        console.log(`[${conn.id} ${source}] Message received`);
        console.dir(msg.contents, { depth: Infinity, customInspect: true });
      }
    });

    conn.on('parseError', (source: string, err: Error) => {
      if (args.ndjson) {
        console.log(JSON.stringify({ ts: utcnow(), ev: 'parseError', conn, source, err: err.message }));
      } else {
        console.log(`[${conn.id} ${source}] Failed to parse message: ${err.message}`);
      }
    });
  });

  await proxy.listen(local);
  if (args.ndjson) {
    console.log(JSON.stringify({ ts: utcnow(), ev: 'listening', addr: proxy.address(), local, target }));
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
      console.log(JSON.stringify({ ts: utcnow(), ev: 'listening', addr, mode: 'oidc', issuer: config.issuer }));
    } else {
      console.log(`OIDC Proxy listening on ${addr.address}:${addr.port}`);
      console.log(`  Issuer: ${config.issuer}`);
      console.log(`  Client ID: ${config.clientId}`);
    }
  });

  proxy.on('backendConnected', () => {
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'backendConnected' }));
    } else {
      console.log('Connected to backend MongoDB');
    }
  });

  proxy.on('newConnection', (conn: { id: number; incoming: string }) => {
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'newConnection', conn }));
    } else {
      console.log(`[${conn.id}] New connection from ${conn.incoming}`);
    }
  });

  proxy.on('connectionClosed', (connId: number) => {
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'connectionClosed', connId }));
    } else {
      console.log(`[${connId}] Connection closed`);
    }
  });

  proxy.on('connectionError', (connId: number, err: Error) => {
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'connectionError', connId, err: err.message }));
    } else {
      console.log(`[${connId}] Connection error: ${err.message}`);
    }
  });

  proxy.on('saslStart', (connId: number, idpInfo: { issuer: string; clientId: string }) => {
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'saslStart', connId, idpInfo }));
    } else {
      console.log(`[${connId}] SASL start - returning IdP info`);
    }
  });

  proxy.on('authAttempt', (connId: number, user: OptionalUser, jwt: Record<string, unknown> | null) => {
    const normalizedUser = normalizeUser(user);
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'authAttempt', connId, user: normalizedUser, jwt }));
    } else {
      console.log(`${formatLogPrefix(connId, normalizedUser)} Attempting JWT authentication: ${JSON.stringify(jwt)}`);
    }
  });

  proxy.on('authSuccess', (connId: number, user: string, subject: string) => {
    const normalizedUser = normalizeUser(user);
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'authSuccess', connId, user: normalizedUser, subject }));
    } else {
      console.log(`[${connId}] [${normalizedUser}] Authentication successful for: ${subject}`);
    }
  });

  proxy.on('authFailed', (connId: number, user: OptionalUser, error: string) => {
    const normalizedUser = normalizeUser(user);
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'authFailed', connId, user: normalizedUser, error }));
    } else {
      console.log(`${formatLogPrefix(connId, normalizedUser)} Authentication failed: ${error}`);
    }
  });

  proxy.on('commandForwarded', (connId: number, user: string, db: string, cmd: string, request: any, response: any) => {
    const normalizedUser = normalizeUser(user);
    if (args.ndjson) {
      console.log(EJSON.stringify({ ts: utcnow(), ev: 'commandForwarded', connId, user: normalizedUser, db, cmd, request, response }));
    } else {
      console.log(`[${connId}] [${normalizedUser}] Forwarded command: ${db}.${cmd}`);
    }
  });

  proxy.on('commandError', (connId: number, user: string, error: string) => {
    const normalizedUser = normalizeUser(user);
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'commandError', connId, user: normalizedUser, error }));
    } else {
      console.log(`[${connId}] [${normalizedUser}] Command error: ${error}`);
    }
  });

  proxy.on('parseError', (connId: number, err: Error) => {
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'parseError', connId, err: err.message }));
    } else {
      console.log(`[${connId}] Parse error: ${err.message}`);
    }
  });

  proxy.on('authRequired', (connId: number, cmdName: string | null) => {
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'authRequired', connId, cmdName }));
    } else {
      console.log(`[${connId}] Auth required for command: ${cmdName || 'unknown'}`);
    }
  });

  proxy.on('debug', (connId: number, user: OptionalUser, message: string) => {
    if (args.logLevel !== 'debug') {
      return;
    }
    const normalizedUser = normalizeUser(user);
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'debug', connId, user: normalizedUser, message }));
    } else {
      console.log(`${formatLogPrefix(connId, normalizedUser)} DEBUG: ${message}`);
    }
  });

  proxy.on('connectionTimeout', (connId: number) => {
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'connectionTimeout', connId }));
    } else {
      console.log(`[${connId}] Connection timed out`);
    }
  });

  proxy.on('reauthRequired', (connId: number, user: OptionalUser, reason: string) => {
    const normalizedUser = normalizeUser(user);
    if (args.ndjson) {
      console.log(JSON.stringify({ ts: utcnow(), ev: 'reauthRequired', connId, user: normalizedUser, reason }));
    } else {
      console.log(`${formatLogPrefix(connId, normalizedUser)} Reauthentication required: ${reason}`);
    }
  });

  await proxy.start();
}

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
