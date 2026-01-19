import net, { NetConnectOpts, Server } from 'net';
import { WireProtocolParser } from '@src/parse-stream';
import { EventEmitter, once } from 'events';
import { ksuid } from '@src/utils/ksuid';

export class ConnectionPair extends EventEmitter {
  connId: string;
  incoming: string;
  bytesIn: number;
  bytesOut: number;

  constructor(info: Pick<ConnectionPair, 'connId' | 'incoming'>) {
    super();
    this.connId = info.connId;
    this.incoming = info.incoming;
    this.bytesIn = 0;
    this.bytesOut = 0;
  }

  toJSON(): Pick<ConnectionPair, 'connId' | 'incoming'> & { bytesIn: number; bytesOut: number } {
    return {
      connId: this.connId,
      incoming: this.incoming,
      bytesIn: this.bytesIn,
      bytesOut: this.bytesOut
    };
  }
}

export class Proxy extends EventEmitter {
  srv: Server;

  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  constructor(target: NetConnectOpts) {
    super();
    this.srv = net.createServer();
    this.srv.on('connection', (conn1) => {
      const conn2 = net.createConnection(target);

      const conn1reader = new WireProtocolParser();
      const conn2reader = new WireProtocolParser();
      const cp = new ConnectionPair({
        connId: ksuid(),
        incoming: `${conn1.remoteAddress}:${conn1.remotePort}`
      });

      conn1.pipe(conn2);
      conn2.pipe(conn1);
      conn1.pipe(conn1reader);
      conn2.pipe(conn2reader);

      // Track bandwidth
      conn1.on('data', (chunk: Buffer) => {
        cp.bytesIn += chunk.length;
      });
      conn2.on('data', (chunk: Buffer) => {
        cp.bytesOut += chunk.length;
      });

      conn1.on('close', () => {
        cp.emit('connectionClosed', 'outgoing');
        conn2.destroy();
        conn1reader.destroy();
      });
      conn2.on('close', () => {
        cp.emit('connectionClosed', 'incoming');
        conn1.destroy();
        conn2reader.destroy();
      });

      conn1.on('error', (err) => {
        cp.emit('connectionError', 'outgoing', err);
      });
      conn2.on('error', (err) => {
        cp.emit('connectionError', 'incoming', err);
      });
      conn1reader.on('message', (msg) => {
        cp.emit('message', 'outgoing', msg);
      });
      conn2reader.on('message', (msg) => {
        cp.emit('message', 'incoming', msg);
      });
      conn1reader.on('error', (err) => {
        cp.emit('parseError', 'outgoing', err);
      });
      conn2reader.on('error', (err) => {
        cp.emit('parseError', 'incoming', err);
      });

      this.emit('newConnection', cp);
    });
  }

  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  async listen(args: any): Promise<void> {
    this.srv.listen(args);
    await once(this.srv, 'listening');
  }

  address(): any {
    return this.srv.address();
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve, reject) =>
      this.srv.close((err) => (err ? reject(err) : resolve()))
    );
  }
}
