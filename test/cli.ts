import assert from 'assert';
import { parseArgs, parseAddress } from '@src/cli';

describe('cli parseArgs', () => {
  it('parses --help flag', () => {
    const args = parseArgs(['node', 'cli.ts', '--help']);
    assert.strictEqual(args.help, true);
  });

  it('parses -h flag', () => {
    const args = parseArgs(['node', 'cli.ts', '-h']);
    assert.strictEqual(args.help, true);
  });

  it('parses --ndjson flag', () => {
    const args = parseArgs(['node', 'cli.ts', '--ndjson']);
    assert.strictEqual(args.ndjson, true);
  });

  it('parses --oidc-mode flag', () => {
    const args = parseArgs(['node', 'cli.ts', '--oidc-mode']);
    assert.strictEqual(args.oidcMode, true);
  });

  it('parses --log-level debug', () => {
    const args = parseArgs(['node', 'cli.ts', '--log-level', 'debug']);
    assert.strictEqual(args.logLevel, 'debug');
  });

  it('parses --log-level info', () => {
    const args = parseArgs(['node', 'cli.ts', '--log-level', 'info']);
    assert.strictEqual(args.logLevel, 'info');
  });

  it('ignores invalid --log-level value', () => {
    const args = parseArgs(['node', 'cli.ts', '--log-level', 'invalid']);
    assert.strictEqual(args.logLevel, 'info'); // default
  });

  it('parses --issuer', () => {
    const args = parseArgs(['node', 'cli.ts', '--issuer', 'https://auth.example.com']);
    assert.strictEqual(args.issuer, 'https://auth.example.com');
  });

  it('parses --client-id', () => {
    const args = parseArgs(['node', 'cli.ts', '--client-id', 'my-client']);
    assert.strictEqual(args.clientId, 'my-client');
  });

  it('parses --connection-string', () => {
    const args = parseArgs(['node', 'cli.ts', '--connection-string', 'mongodb://localhost:27017']);
    assert.strictEqual(args.connectionString, 'mongodb://localhost:27017');
  });

  it('parses --jwks-uri', () => {
    const args = parseArgs(['node', 'cli.ts', '--jwks-uri', 'https://auth.example.com/jwks']);
    assert.strictEqual(args.jwksUri, 'https://auth.example.com/jwks');
  });

  it('parses --audience', () => {
    const args = parseArgs(['node', 'cli.ts', '--audience', 'https://api.example.com']);
    assert.strictEqual(args.audience, 'https://api.example.com');
  });

  it('collects positional arguments', () => {
    const args = parseArgs(['node', 'cli.ts', 'localhost:27017', 'localhost:3000']);
    assert.deepStrictEqual(args.positional, ['localhost:27017', 'localhost:3000']);
  });

  it('parses multiple flags together', () => {
    const args = parseArgs([
      'node', 'cli.ts',
      '--ndjson',
      '--oidc-mode',
      '--issuer', 'https://auth.example.com',
      '--client-id', 'test-client',
      '--connection-string', 'mongodb://localhost:27017',
      '--jwks-uri', 'https://auth.example.com/jwks',
      '--audience', 'https://api.example.com',
      '--log-level', 'debug',
      '3000'
    ]);
    assert.strictEqual(args.ndjson, true);
    assert.strictEqual(args.oidcMode, true);
    assert.strictEqual(args.issuer, 'https://auth.example.com');
    assert.strictEqual(args.clientId, 'test-client');
    assert.strictEqual(args.connectionString, 'mongodb://localhost:27017');
    assert.strictEqual(args.jwksUri, 'https://auth.example.com/jwks');
    assert.strictEqual(args.audience, 'https://api.example.com');
    assert.strictEqual(args.logLevel, 'debug');
    assert.deepStrictEqual(args.positional, ['3000']);
  });

  it('ignores unknown flags starting with --', () => {
    const args = parseArgs(['node', 'cli.ts', '--unknown-flag', 'value']);
    assert.strictEqual((args as any).unknownFlag, undefined);
    assert.deepStrictEqual(args.positional, ['value']);
  });

  it('handles missing value for --log-level at end', () => {
    const args = parseArgs(['node', 'cli.ts', '--log-level']);
    assert.strictEqual(args.logLevel, 'info'); // stays default
  });

  it('returns defaults when no args provided', () => {
    const args = parseArgs(['node', 'cli.ts']);
    assert.strictEqual(args.help, false);
    assert.strictEqual(args.ndjson, false);
    assert.strictEqual(args.oidcMode, false);
    assert.strictEqual(args.logLevel, 'info');
    assert.strictEqual(args.issuer, undefined);
    assert.strictEqual(args.clientId, undefined);
    assert.strictEqual(args.connectionString, undefined);
    assert.strictEqual(args.jwksUri, undefined);
    assert.strictEqual(args.audience, undefined);
    assert.deepStrictEqual(args.positional, []);
  });
});

describe('cli parseAddress', () => {
  it('parses host:port format', () => {
    const addr = parseAddress('localhost:27017');
    assert.deepStrictEqual(addr, { host: 'localhost', port: 27017 });
  });

  it('parses port-only format with default host', () => {
    const addr = parseAddress('3000');
    assert.deepStrictEqual(addr, { host: 'localhost', port: 3000 });
  });

  it('parses Unix socket path starting with /', () => {
    const addr = parseAddress('/var/run/mongodb.sock');
    assert.deepStrictEqual(addr, { path: '/var/run/mongodb.sock' });
  });

  it('parses Windows path containing backslash', () => {
    const addr = parseAddress('C:\\temp\\mongodb.sock');
    assert.deepStrictEqual(addr, { path: 'C:\\temp\\mongodb.sock' });
  });

  it('parses IP address with port', () => {
    const addr = parseAddress('127.0.0.1:27017');
    assert.deepStrictEqual(addr, { host: '127.0.0.1', port: 27017 });
  });

  it('parses 0 for random port', () => {
    const addr = parseAddress('0');
    assert.deepStrictEqual(addr, { host: 'localhost', port: 0 });
  });

  it('parses hostname with port', () => {
    const addr = parseAddress('db.example.com:27017');
    assert.deepStrictEqual(addr, { host: 'db.example.com', port: 27017 });
  });
});
