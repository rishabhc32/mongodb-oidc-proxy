import assert from 'assert';
import { Proxy } from '@src/proxy';
import { MongoClient } from 'mongodb';
import childProcess from 'child_process';
import { EJSON } from 'bson';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { once } from 'events';
import { setTimeout } from 'timers/promises';

let hostport: string;
before(() => {
  if (!process.env.MONGODB_HOSTPORT) {
    throw new Error('MONGODB_HOSTPORT not set');
  }
  hostport = process.env.MONGODB_HOSTPORT;
});

describe('Proxy', function () {
  this.timeout(10_000);

  let proxy: Proxy;
  let port: number;
  let events: any[];
  let client: MongoClient;

  beforeEach(async () => {
    events = [];
    proxy = new Proxy({ host: hostport.split(':')[0], port: +hostport.split(':')[1] });
    proxy.on('newConnection', (conn: any) => {
      conn.on('connectionClosed', (source: string) => events.push({ ev: 'connectionClosed', source }));
      conn.on('connectionError', (source: string, err: Error) => events.push({ ev: 'connectionError', source, err }));
      conn.on('message', (source: string, msg: any) => events.push({ ev: 'message', source, msg }));
      conn.on('parseError', (source: string, err: Error) => events.push({ ev: 'parseError', source, err }));
    });
    await proxy.listen(0);
    port = proxy.address().port;
    client = await MongoClient.connect(`mongodb://localhost:${port}`);
  });

  afterEach(async () => {
    await client.close();
    await proxy.close();
  });

  it('records ismaster events', async () => {
    assert(
      events.some((ev) => ev.source === 'outgoing' && ev.msg?.contents.query?.data?.ismaster),
      EJSON.stringify(events) + ' is missing ismaster query'
    );
    assert(
      events.some((ev) => ev.source === 'incoming' && ev.msg?.contents.documents?.[0]?.data?.ismaster),
      EJSON.stringify(events) + ' is missing ismaster reply'
    );
  });

  it('records find queries', async () => {
    await client.db('test').collection('test').findOne();
    assert(
      events.some((ev) => ev.source === 'outgoing' && ev.msg?.contents.sections?.[0]?.body?.data?.find === 'test'),
      EJSON.stringify(events) + ' is missing findOne query'
    );
    assert(
      events.some((ev) => ev.source === 'incoming' && ev.msg?.contents.sections?.[0]?.body?.data?.cursor),
      EJSON.stringify(events) + ' is missing findOne reply'
    );
  });
});

describe('Proxy close', function () {
  this.timeout(10_000);

  it('closes open connections', async () => {
    const proxy = new Proxy({ host: hostport.split(':')[0], port: +hostport.split(':')[1] });
    const closed: string[] = [];
    proxy.on('newConnection', (conn: any) => conn.on('connectionClosed', (source: string) => closed.push(source)));
    await proxy.listen(0);
    const client = await MongoClient.connect(`mongodb://localhost:${proxy.address().port}`);

    try {
      await proxy.close();
      assert(closed.includes('outgoing') && closed.includes('incoming'), `closed: ${closed}`);
    } finally {
      await client.close();
    }
  });
});

describe('bin', function () {
  this.timeout(10_000);

  let proc: childProcess.ChildProcess;
  let port: number;
  let stdout: string;
  let client: MongoClient;

  describe('human-readable', () => {
    beforeEach(async () => {
      proc = childProcess.spawn(
        'ts-node',
        [
          '-P',
          path.join(__dirname, '..', 'tsconfig.json'),
          '-r',
          'tsconfig-paths/register',
          path.join(__dirname, '..', 'src', 'cli.ts'),
          hostport,
          'localhost:0'
        ],
        { stdio: 'pipe' }
      );
      port = 0;
      await new Promise<void>((resolve) => {
        stdout = '';
        (proc.stdout as any).setEncoding('utf8');
        (proc.stdout as any).on('data', (chunk: string) => {
          stdout += chunk;
          if (!port) {
            const match = stdout.match(/Listening on(.+)forwarding/);
            if (match) {
              // eslint-disable-next-line no-eval
              port = eval(`(${match[1]}).port`);
              resolve();
            }
          }
        });
      });
      client = await MongoClient.connect(`mongodb://localhost:${port}`);
    });

    afterEach(async () => {
      await client.close();
      proc.kill();
      await once(proc, 'exit');
    });

    it('records ismaster events', async () => {
      await client.db('test').collection('test').findOne();
      assert.match(stdout, /ismaster: true/);
      assert.match(stdout, /ok: 1/);
    });

    it('records find queries', async () => {
      await client.db('test').collection('test').findOne();
      assert.match(stdout, /find: 'test'/);
    });
  });

  describe('ndjson --log-file', () => {
    let logFile: string;
    let tmpDir: string;

    const parseNdjsonLines = (output: string) =>
      output
        .split('\n')
        .map((line) => {
          try {
            return JSON.parse(line);
          } catch {
            return null;
          }
        })
        .filter(Boolean);

    // Poll rather than fs.watch: watch events can be coalesced (e.g. FSEvents
    // on macOS), so the write carrying the event may never be observed
    const waitForLogEvent = async (filePath: string, evName: string) => {
      for (;;) {
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const event = parseNdjsonLines(content).find((e) => e.ev === evName);
          if (event) return event;
        } catch {}
        await setTimeout(50);
      }
    };

    beforeEach(async () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-test-'));
      logFile = path.join(tmpDir, 'proxy.log');
      proc = childProcess.spawn(
        'ts-node',
        [
          '-P',
          path.join(__dirname, '..', 'tsconfig.json'),
          '-r',
          'tsconfig-paths/register',
          path.join(__dirname, '..', 'src', 'cli.ts'),
          '--ndjson',
          '--log-file',
          logFile,
          hostport,
          'localhost:0'
        ],
        { stdio: 'pipe' }
      );
      stdout = '';
      (proc.stdout as any).setEncoding('utf8');
      (proc.stdout as any).on('data', (chunk: string) => {
        stdout += chunk;
      });
      // Wait for listening event to appear in the log file
      const listening = await waitForLogEvent(logFile, 'listening');
      port = listening.addr.port;
      client = await MongoClient.connect(`mongodb://localhost:${port}`);
    });

    afterEach(async () => {
      await client?.close();
      if (proc.exitCode === null && proc.signalCode === null) {
        proc.kill();
        await once(proc, 'exit');
      }
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('writes ndjson events to log file', async () => {
      await client.db('test').collection('test').findOne();
      const content = fs.readFileSync(logFile, 'utf8');
      const events = parseNdjsonLines(content);
      assert(
        events.some((e) => e.ev === 'listening'),
        'log file should contain listening event'
      );
      assert(
        events.some((e) => e.ev === 'commandForwarded'),
        'log file should contain commandForwarded events'
      );
    });

    it('closes connections, flushes the log and exits 0 on SIGTERM', async () => {
      await client.db('test').collection('test').findOne();
      const exited = once(proc, 'exit');
      proc.kill('SIGTERM');
      const [code, signal] = await exited;
      assert.strictEqual(signal, null);
      assert.strictEqual(code, 0);
      const events = parseNdjsonLines(fs.readFileSync(logFile, 'utf8'));
      assert(
        events.some((e) => e.ev === 'connectionClosed'),
        'log file should contain the connectionClosed events written during shutdown'
      );
    });

    it('does not write ndjson to stdout when --log-file is used', async () => {
      await client.db('test').collection('test').findOne();
      const ndjsonLines = parseNdjsonLines(stdout);
      assert.strictEqual(ndjsonLines.length, 0, 'stdout should not contain NDJSON when --log-file is used');
    });
  });

  describe('ndjson', () => {
    const parseNdjsonLines = (output: string) =>
      output
        .split('\n')
        .map((line) => {
          try {
            return JSON.parse(line);
          } catch {
            return null;
          }
        })
        .filter(Boolean);

    beforeEach(async () => {
      proc = childProcess.spawn(
        'ts-node',
        [
          '-P',
          path.join(__dirname, '..', 'tsconfig.json'),
          '-r',
          'tsconfig-paths/register',
          path.join(__dirname, '..', 'src', 'cli.ts'),
          '--ndjson',
          hostport,
          'localhost:0'
        ],
        { stdio: 'pipe' }
      );
      port = 0;
      await new Promise<void>((resolve) => {
        stdout = '';
        (proc.stdout as any).setEncoding('utf8');
        (proc.stdout as any).on('data', (chunk: string) => {
          stdout += chunk;
          if (!port) {
            const listening = stdout
              .split('\n')
              .map((line) => {
                try {
                  return JSON.parse(line);
                } catch {
                  return {};
                }
              })
              .find((line) => line.ev === 'listening');
            if (listening) {
              port = listening.addr.port;
              resolve();
            }
          }
        });
      });
      client = await MongoClient.connect(`mongodb://localhost:${port}`);
    });

    afterEach(async () => {
      await client.close();
      proc.kill();
      await once(proc, 'exit');
    });

    it('records ismaster events', async () => {
      await client.db('test').collection('test').findOne();
      assert.match(stdout, /"ismaster":true/);
      assert.match(stdout, /"ok":1/);
    });

    it('records find queries', async () => {
      await client.db('test').collection('test').findOne();
      assert.match(stdout, /"find":"test"/);
      const events = parseNdjsonLines(stdout).filter((event) => event.ev === 'commandForwarded');
      assert(events.length > 0, 'missing commandForwarded events');
      const outgoing = events.find((event) => event.source === 'outgoing');
      const incoming = events.find((event) => event.source === 'incoming');
      assert(outgoing && outgoing.requestBytes > 0, 'missing outgoing requestBytes');
      assert(incoming && incoming.responseBytes > 0, 'missing incoming responseBytes');
    });
  });
});
