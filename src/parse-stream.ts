import { ParseMessage, type ParseOptions } from '@src/parse';
import { Writable } from 'stream';

export class WireProtocolParser extends Writable {
  buffer: Uint8Array[];
  currentNeed: number;
  options: ParseOptions;

  constructor(options: ParseOptions = {}) {
    super();
    this.buffer = [];
    this.currentNeed = 0;
    this.options = options;
  }

  async _write(chunk: Uint8Array, encoding: unknown, callback: (err?: Error) => void): Promise<void> {
    try {
      this.buffer.push(chunk);
      if (chunk.length < this.currentNeed) {
        this.currentNeed -= chunk.length;
      } else {
        const acc = Buffer.concat(this.buffer);
        const result = await ParseMessage(acc, this.options);
        if ('needBytes' in result) {
          this.buffer = [acc];
          this.currentNeed = result.needBytes;
        } else {
          this.emit('message', result.msg);
          this.buffer = [];
          this.currentNeed = 0;
          this._write(acc.subarray(result.readBytes), null, callback);
          return;
        }
      }
      callback();
    } catch (err) {
      // eslint-disable-next-line standard/no-callback-literal
      callback(err as Error);
    }
  }
}
