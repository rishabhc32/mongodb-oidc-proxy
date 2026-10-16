import assert from 'assert';
import zlib from 'zlib';
import { once } from 'events';
import { serialize } from 'bson';
import { ParseMessage, OpCode, MAX_MESSAGE_SIZE_BYTES } from '@src/parse';
import { WireProtocolParser } from '@src/parse-stream';

function header(messageLength: number, opCode: number): Buffer {
  const buf = Buffer.alloc(16);
  buf.writeInt32LE(messageLength, 0);
  buf.writeInt32LE(1, 4);
  buf.writeInt32LE(0, 8);
  buf.writeInt32LE(opCode, 12);
  return buf;
}

// OP_MSG body: flagBits + kind 0 section + BSON document
function opMsgBody(doc: Record<string, unknown>): Buffer {
  return Buffer.concat([Buffer.alloc(4), Buffer.from([0]), Buffer.from(serialize(doc))]);
}

function opMsg(doc: Record<string, unknown>): Buffer {
  const body = opMsgBody(doc);
  return Buffer.concat([header(16 + body.length, OpCode.OP_MSG), body]);
}

function opCompressed(originalOpcode: number, uncompressedSize: number, compressorId: number, payload: Buffer): Buffer {
  const fields = Buffer.alloc(9);
  fields.writeInt32LE(originalOpcode, 0);
  fields.writeInt32LE(uncompressedSize, 4);
  fields.writeUInt8(compressorId, 8);
  const body = Buffer.concat([fields, payload]);
  return Buffer.concat([header(16 + body.length, OpCode.OP_COMPRESSED), body]);
}

describe('ParseMessage', () => {
  it('parses a valid OP_MSG', async () => {
    const data = opMsg({ ping: 1, $db: 'admin' });
    const result = await ParseMessage(data);
    assert('msg' in result);
    assert.strictEqual(result.readBytes, data.length);
    assert.strictEqual((result.msg.contents as any).sections[0].body.data.ping, 1);
  });

  it('reports the remaining bytes needed', async () => {
    const data = opMsg({ ping: 1 });
    assert.deepStrictEqual(await ParseMessage(data.subarray(0, 10)), { needBytes: 6 });
    assert.deepStrictEqual(await ParseMessage(data.subarray(0, 20)), { needBytes: data.length - 20 });
  });

  for (const messageLength of [0, -16, 15]) {
    it(`rejects a declared message length of ${messageLength}`, async () => {
      await assert.rejects(ParseMessage(header(messageLength, 9999)), /Invalid message length/);
    });
  }

  it('rejects a declared message length above the maximum message size', async () => {
    await assert.rejects(ParseMessage(header(MAX_MESSAGE_SIZE_BYTES + 1, OpCode.OP_MSG)), /Invalid message length/);
  });

  it('consumes a header-only message with an unknown opcode', async () => {
    const result = await ParseMessage(header(16, 9999));
    assert('msg' in result);
    assert.strictEqual(result.readBytes, 16);
  });

  it('rejects a section that extends past the end of the message', async () => {
    const message = opMsg({ ping: 1 });
    // Declare a document larger than the message and place extra bytes after it,
    // as when the message is a slice of a larger shared allocation
    message.writeUInt32LE(message.length, 21);
    const backing = Buffer.concat([message, Buffer.alloc(64, 1)]);
    await assert.rejects(ParseMessage(backing.subarray(0, message.length)), /Out of bounds/);
  });

  it('rejects an empty document in a document sequence', async () => {
    const seqId = Buffer.from('documents\0');
    const section = Buffer.alloc(5);
    section.writeUInt8(1, 0);
    section.writeUInt32LE(4 + seqId.length + 4, 1);
    const emptyDoc = Buffer.alloc(4); // declared size 0
    const body = Buffer.concat([Buffer.alloc(4), section, seqId, emptyDoc]);
    await assert.rejects(ParseMessage(Buffer.concat([header(16 + body.length, OpCode.OP_MSG), body])), /bson size must be >= 5/);
  });

  describe('OP_COMPRESSED', () => {
    const original = opMsgBody({ ping: 1, $db: 'admin' });

    it('parses a zlib-compressed message of the declared size', async () => {
      const data = opCompressed(OpCode.OP_MSG, original.length, 2, zlib.deflateSync(original));
      const result = await ParseMessage(data);
      assert('msg' in result);
      const contents = (result.msg.contents as any).contents;
      assert.strictEqual(contents.sections[0].body.data.ping, 1);
    });

    it('rejects compressed messages when not allowed', async () => {
      const data = opCompressed(OpCode.OP_MSG, original.length, 2, zlib.deflateSync(original));
      await assert.rejects(ParseMessage(data, { allowCompressed: false }), /not accepted/);
    });

    it('rejects nested compressed messages', async () => {
      const data = opCompressed(OpCode.OP_COMPRESSED, original.length, 2, zlib.deflateSync(original));
      await assert.rejects(ParseMessage(data), /Nested compressed messages/);
    });

    it('rejects a payload that inflates beyond its declared size', async () => {
      const data = opCompressed(OpCode.OP_MSG, 8, 2, zlib.deflateSync(Buffer.alloc(4096)));
      await assert.rejects(ParseMessage(data));
    });

    it('rejects a declared size above the maximum message size', async () => {
      const data = opCompressed(OpCode.OP_MSG, MAX_MESSAGE_SIZE_BYTES + 1, 2, zlib.deflateSync(original));
      await assert.rejects(ParseMessage(data), /Invalid uncompressed message size/);
    });
  });
});

describe('WireProtocolParser', () => {
  it('emits a message delivered in small chunks', async () => {
    const parser = new WireProtocolParser();
    const data = opMsg({ ping: 1, $db: 'admin' });
    const received = once(parser, 'message');
    for (let i = 0; i < data.length; i += 7) {
      parser.write(data.subarray(i, i + 7));
    }
    const [msg] = await received;
    assert.strictEqual(msg.contents.sections[0].body.data.ping, 1);
  });

  it('emits back-to-back messages from one chunk', async () => {
    const parser = new WireProtocolParser();
    const messages: any[] = [];
    parser.on('message', (msg) => messages.push(msg));
    parser.write(Buffer.concat([opMsg({ a: 1 }), opMsg({ b: 1 })]));
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepStrictEqual(
      messages.map((m) => Object.keys(m.contents.sections[0].body.data)[0]),
      ['a', 'b']
    );
  });

  it('errors on an invalid message length instead of re-parsing it', async () => {
    const parser = new WireProtocolParser();
    let messages = 0;
    parser.on('message', () => {
      messages++;
    });
    const errored = once(parser, 'error');
    parser.write(header(0, 9999));
    const [err] = await errored;
    assert.match(err.message, /Invalid message length/);
    assert.strictEqual(messages, 0);
  });
});
