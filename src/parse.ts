import zlib from 'zlib';
import { promisify, TextDecoder } from 'util';
import { type Binary, type Document, deserialize } from 'bson';

// Largest message MongoDB accepts (its advertised maxMessageSizeBytes)
export const MAX_MESSAGE_SIZE_BYTES = 48000000;

// Bounds-checked view of buf[offset, offset + size). buf is often a slice of a
// larger shared allocation (Node's Buffer pool), so views must never be built
// from buf.buffer directly or they can expose memory past the message
function view(buf: Uint8Array, length: number, offset: number, size: number): Uint8Array {
  if (!Number.isInteger(offset) || !Number.isInteger(size) || offset < 0 || size < 0 || offset + size > length) {
    throw new RangeError(`Out of bounds read at offset ${offset} with size ${size} (message length ${length})`);
  }
  return buf.subarray(offset, offset + size);
}

class MessageHeader {
  messageLength: number;
  requestID: number;
  responseTo: number;
  opCode: number;

  constructor(values: Pick<MessageHeader, 'messageLength' | 'requestID' | 'responseTo' | 'opCode'>) {
    this.messageLength = values.messageLength;
    this.requestID = values.requestID;
    this.responseTo = values.responseTo;
    this.opCode = values.opCode;
  }

  static async Read(buf: Uint8Array): Promise<{ msg: MessageHeader; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, 4 * 4);
    return {
      msg: new this({
        messageLength: dv.getInt32(0, true),
        requestID: dv.getInt32(4, true),
        responseTo: dv.getInt32(8, true),
        opCode: dv.getInt32(12, true)
      }),
      readBytes: 4 * 4
    };
  }
}

class OpCode {
  static OP_MSG = 2013;
  static OP_REPLY = 1;
  static OP_UPDATE = 2001;
  static OP_INSERT = 2002;
  static OP_QUERY = 2004;
  static OP_GET_MORE = 2005;
  static OP_DELETE = 2006;
  static OP_KILL_CURSORS = 2007;
  static OP_COMPRESSED = 2012;

  static LookupOpCode(value: (typeof OpCode)[keyof OpCode]): keyof OpCode | null {
    for (const key of Object.keys(OpCode) as (keyof OpCode)[]) {
      if (OpCode[key] === value) {
        return key;
      }
    }
    return null;
  }
}

type OpContents =
  OpMsg | OpReply | OpUpdate | OpInsert | OpQuery | OpGetMore | OpDelete | OpKillCursors | OpCompressed | OpUnknown;

class BSONBuffer {
  data: any;
  decodedPayload?: any;

  constructor(buf: Uint8Array) {
    this.data = deserialize(buf);
    let payload: undefined | Binary;
    if (
      (this.data.saslStart || this.data.saslContinue || this.data.conversationId) &&
      this.data.payload?._bsontype === 'Binary'
    ) {
      payload = this.data.payload;
    }
    if (this.data.speculativeAuthenticate?.payload?._bsontype === 'Binary') {
      payload = this.data.speculativeAuthenticate.payload;
    }
    try {
      if (payload) {
        this.decodedPayload = deserialize(payload.value());
      }
    } catch (err) {}
  }
}

class OpMsgBodySection {
  kind = 'Body' as const;
  body: BSONBuffer;

  constructor(body: BSONBuffer) {
    this.body = body;
  }
}

class OpMsgSecurityTokenSection {
  kind = 'SecurityToken' as const;
  body: BSONBuffer;

  constructor(body: BSONBuffer) {
    this.body = body;
  }
}

class OpMsgDocumentSequenceSection {
  kind = 'DocumentSequence' as const;
  docSequenceId: string;
  objects: BSONBuffer[];

  constructor(docSequenceId: string, objects: BSONBuffer[]) {
    this.docSequenceId = docSequenceId;
    this.objects = objects;
  }
}

class OpMsgUnknownSection {
  kind = 'Unknown' as const;
  kindByte: number;

  constructor(kindByte: number) {
    this.kindByte = kindByte;
  }
}

class OpMsg {
  opCode = 'OP_MSG' as const;
  flagBits: number;
  sections: (OpMsgBodySection | OpMsgDocumentSequenceSection | OpMsgSecurityTokenSection | OpMsgUnknownSection)[];
  checksum: number | null;

  constructor(values: Pick<OpMsg, 'flagBits' | 'sections' | 'checksum'>) {
    this.flagBits = values.flagBits;
    this.sections = values.sections;
    this.checksum = values.checksum;
  }

  static async Read(buf: Uint8Array, length: number): Promise<{ msg: OpMsg; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, length);
    const flagBits = dv.getUint32(0, true);
    const checksum = flagBits & 1 ? dv.getUint32(length - 4, true) : null;
    const sections: OpMsg['sections'] = [];
    let i: number;
    for (i = 4; i < (flagBits & 1 ? length - 4 : length);) {
      const kind = dv.getUint8(i);
      switch (kind) {
        case 0:
          {
            const bsonSize = dv.getUint32(i + 1, true);
            sections.push(new OpMsgBodySection(new BSONBuffer(view(buf, length, i + 1, bsonSize))));
            i += 1 + bsonSize;
          }
          break;
        case 1:
          {
            const sectionSize = dv.getUint32(i + 1, true);
            const seqIdStart = i + 5;
            for (i = seqIdStart; i < seqIdStart - 4 + sectionSize; i++) {
              if (dv.getUint8(i) === 0) {
                break;
              }
            }
            const docSequenceId = new TextDecoder().decode(view(buf, length, seqIdStart, i - seqIdStart));
            const objects: BSONBuffer[] = [];
            for (i = i + 1; i < seqIdStart - 4 + sectionSize;) {
              const bsonSize = dv.getUint32(i, true);
              objects.push(new BSONBuffer(view(buf, length, i, bsonSize)));
              i += bsonSize;
            }
            sections.push(new OpMsgDocumentSequenceSection(docSequenceId, objects));
          }
          break;
        case 2:
          {
            const bsonSize = dv.getUint32(i + 1, true);
            sections.push(new OpMsgSecurityTokenSection(new BSONBuffer(view(buf, length, i + 1, bsonSize))));
            i += 1 + bsonSize;
          }
          break;
        default: {
          sections.push(new OpMsgUnknownSection(kind));
          i = length;
          break;
        }
      }
    }

    return {
      msg: new this({
        flagBits,
        sections,
        checksum
      }),
      readBytes: i + (flagBits & 1) ? 4 : 0
    };
  }
}

class OpUpdate {
  opCode = 'OP_UPDATE' as const;
  fullCollectionName: string;
  flags: number;
  selector: BSONBuffer;
  update: BSONBuffer;

  constructor(values: Pick<OpUpdate, 'fullCollectionName' | 'flags' | 'selector' | 'update'>) {
    this.fullCollectionName = values.fullCollectionName;
    this.flags = values.flags;
    this.selector = values.selector;
    this.update = values.update;
  }

  static async Read(buf: Uint8Array, length: number): Promise<{ msg: OpUpdate; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, length);
    let i;
    for (i = 4; i < length; i++) {
      if (dv.getUint8(i) === 0) {
        break;
      }
    }
    const fullCollectionName = new TextDecoder().decode(view(buf, length, 4, i - 4));
    i++;
    const flags = dv.getInt32(i, true);
    let selector: BSONBuffer;
    let update: BSONBuffer;
    {
      const bsonSize = dv.getUint32(i, true);
      selector = new BSONBuffer(view(buf, length, i, bsonSize));
      i += bsonSize;
    }
    {
      const bsonSize = dv.getUint32(i, true);
      update = new BSONBuffer(view(buf, length, i, bsonSize));
      i += bsonSize;
    }

    return {
      msg: new this({
        fullCollectionName,
        flags,
        selector,
        update
      }),
      readBytes: i
    };
  }
}

class OpInsert {
  opCode = 'OP_INSERT' as const;
  fullCollectionName: string;
  flags: number;
  documents: BSONBuffer[];

  constructor(values: Pick<OpInsert, 'fullCollectionName' | 'flags' | 'documents'>) {
    this.fullCollectionName = values.fullCollectionName;
    this.flags = values.flags;
    this.documents = values.documents;
  }

  static async Read(buf: Uint8Array, length: number): Promise<{ msg: OpInsert; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, length);
    let i = 0;
    const flags = dv.getInt32(i, true);
    for (i = 4; i < length; i++) {
      if (dv.getUint8(i) === 0) {
        break;
      }
    }
    const fullCollectionName = new TextDecoder().decode(view(buf, length, 4, i - 4));
    i++;
    const documents: BSONBuffer[] = [];
    while (i < length) {
      const bsonSize = dv.getUint32(i, true);
      documents.push(new BSONBuffer(view(buf, length, i, bsonSize)));
      i += bsonSize;
    }

    return {
      msg: new this({
        fullCollectionName,
        flags,
        documents
      }),
      readBytes: i
    };
  }
}

class OpQuery {
  opCode = 'OP_QUERY' as const;
  fullCollectionName: string;
  flags: number;
  numberToSkip: number;
  numberToReturn: number;
  query: BSONBuffer;
  returnFieldsSelector: BSONBuffer | null;

  constructor(
    values: Pick<
      OpQuery,
      'fullCollectionName' | 'flags' | 'numberToSkip' | 'numberToReturn' | 'query' | 'returnFieldsSelector'
    >
  ) {
    this.fullCollectionName = values.fullCollectionName;
    this.flags = values.flags;
    this.numberToSkip = values.numberToSkip;
    this.numberToReturn = values.numberToReturn;
    this.query = values.query;
    this.returnFieldsSelector = values.returnFieldsSelector;
  }

  static async Read(buf: Uint8Array, length: number): Promise<{ msg: OpQuery; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, length);
    let i = 0;
    const flags = dv.getInt32(i, true);
    for (i = 4; i < length; i++) {
      if (dv.getUint8(i) === 0) {
        break;
      }
    }
    const fullCollectionName = new TextDecoder().decode(view(buf, length, 4, i - 4));
    i++;

    const numberToSkip = dv.getInt32(i, true);
    i += 4;
    const numberToReturn = dv.getInt32(i, true);
    i += 4;

    let query: BSONBuffer;
    let returnFieldsSelector: BSONBuffer | null = null;
    {
      const bsonSize = dv.getUint32(i, true);
      query = new BSONBuffer(view(buf, length, i, bsonSize));
      i += bsonSize;
    }
    if (i < length) {
      const bsonSize = dv.getUint32(i, true);
      returnFieldsSelector = new BSONBuffer(view(buf, length, i, bsonSize));
      i += bsonSize;
    }

    return {
      msg: new this({
        fullCollectionName,
        flags,
        numberToSkip,
        numberToReturn,
        query,
        returnFieldsSelector
      }),
      readBytes: i
    };
  }
}

class OpGetMore {
  opCode = 'OP_GET_MORE' as const;
  fullCollectionName: string;
  numberToReturn: number;
  cursorId: string;

  constructor(values: Pick<OpGetMore, 'fullCollectionName' | 'numberToReturn' | 'cursorId'>) {
    this.fullCollectionName = values.fullCollectionName;
    this.numberToReturn = values.numberToReturn;
    this.cursorId = values.cursorId;
  }

  static async Read(buf: Uint8Array, length: number): Promise<{ msg: OpGetMore; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, length);
    let i;
    for (i = 4; i < length; i++) {
      if (dv.getUint8(i) === 0) {
        break;
      }
    }
    const fullCollectionName = new TextDecoder().decode(view(buf, length, 4, i - 4));
    i++;

    const numberToReturn = dv.getInt32(i, true);
    i += 4;
    const cursorId = String(dv.getBigInt64(i, true));
    i += 8;

    return {
      msg: new this({
        fullCollectionName,
        numberToReturn,
        cursorId
      }),
      readBytes: i
    };
  }
}

class OpDelete {
  opCode = 'OP_DELETE' as const;
  fullCollectionName: string;
  flags: number;
  selector: BSONBuffer;

  constructor(values: Pick<OpDelete, 'fullCollectionName' | 'flags' | 'selector'>) {
    this.fullCollectionName = values.fullCollectionName;
    this.flags = values.flags;
    this.selector = values.selector;
  }

  static async Read(buf: Uint8Array, length: number): Promise<{ msg: OpDelete; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, length);
    let i;
    for (i = 4; i < length; i++) {
      if (dv.getUint8(i) === 0) {
        break;
      }
    }
    const fullCollectionName = new TextDecoder().decode(view(buf, length, 4, i - 4));
    i++;

    const flags = dv.getInt32(i, true);
    i += 4;

    let selector: BSONBuffer;
    {
      const bsonSize = dv.getUint32(i, true);
      selector = new BSONBuffer(view(buf, length, i, bsonSize));
      i += bsonSize;
    }

    return {
      msg: new this({
        fullCollectionName,
        flags,
        selector
      }),
      readBytes: i
    };
  }
}

class OpKillCursors {
  opCode = 'OP_KILL_CURSORS' as const;
  cursorIds: string[];

  constructor(values: Pick<OpKillCursors, 'cursorIds'>) {
    this.cursorIds = values.cursorIds;
  }

  static async Read(buf: Uint8Array, length: number): Promise<{ msg: OpKillCursors; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, length);
    const n = dv.getInt32(4, true);
    const cursorIds: string[] = [];
    let i;
    for (i = 8; i - 8 < n * 8; i += 8) {
      cursorIds.push(String(dv.getBigInt64(i, true)));
    }

    return {
      msg: new this({
        cursorIds
      }),
      readBytes: i
    };
  }
}

class OpCompressed {
  opCode = 'OP_COMPRESSED' as const;
  originalOpcode: number;
  compressorId: string;
  contents: OpContents | Uint8Array;

  constructor(values: Pick<OpCompressed, 'originalOpcode' | 'compressorId' | 'contents'>) {
    this.originalOpcode = values.originalOpcode;
    this.compressorId = values.compressorId;
    this.contents = values.contents;
  }

  static async Read(
    buf: Uint8Array,
    length: number,
    maxMessageSize: number
  ): Promise<{ msg: OpCompressed; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, length);
    const originalOpcode = dv.getInt32(0, true);
    const uncompressedSize = dv.getInt32(4, true);
    const compressorIdN = dv.getUint8(8);

    // Bound decompression up front: a small payload can inflate to gigabytes
    if (originalOpcode === OpCode.OP_COMPRESSED) {
      throw new Error('Nested compressed messages are not accepted');
    }
    // The decompressed message, header included, must fit the same limit as any other
    if (uncompressedSize < 0 || 16 + uncompressedSize > maxMessageSize) {
      throw new RangeError(`Invalid uncompressed message size ${uncompressedSize}`);
    }
    let compressorId: string;
    switch (compressorIdN) {
      case 0:
        compressorId = 'noop';
        break;
      case 1:
        compressorId = 'snappy';
        break;
      case 2:
        compressorId = 'zlib';
        break;
      case 3:
        compressorId = 'zstd';
        break;
      default:
        compressorId = `unknown (${compressorIdN})`;
        break;
    }

    const compressed = view(buf, length, 9, length - 9);
    let uncompressed: Uint8Array | null = null;
    if (compressorId === 'noop') {
      uncompressed = compressed;
    } else if (compressorId === 'zlib') {
      uncompressed = await promisify(zlib.inflate)(compressed, { maxOutputLength: Math.max(uncompressedSize, 1) });
    }

    let contents: OpContents | Uint8Array;
    if (uncompressed === null) {
      contents = compressed;
    } else {
      contents = (await ReadOpContents(originalOpcode, uncompressed, uncompressed.length, maxMessageSize)).msg;
    }

    return {
      msg: new this({
        originalOpcode,
        compressorId,
        contents
      }),
      readBytes: length
    };
  }
}

class OpReply {
  opCode = 'OP_REPLY' as const;
  flags: number;
  cursorId: string;
  startingFrom: number;
  numberReturned: number;
  documents: BSONBuffer[];

  constructor(values: Pick<OpReply, 'flags' | 'cursorId' | 'startingFrom' | 'numberReturned' | 'documents'>) {
    this.flags = values.flags;
    this.cursorId = values.cursorId;
    this.startingFrom = values.startingFrom;
    this.numberReturned = values.numberReturned;
    this.documents = values.documents;
  }

  static async Read(buf: Uint8Array, length: number): Promise<{ msg: OpReply; readBytes: number }> {
    const dv = new DataView(buf.buffer, buf.byteOffset, length);
    let i = 0;
    const flags = dv.getInt32(i, true);
    i += 4;
    const cursorId = String(dv.getBigUint64(i, true));
    i += 8;
    const startingFrom = dv.getInt32(i, true);
    i += 4;
    const numberReturned = dv.getInt32(i, true);
    i += 4;

    const documents: BSONBuffer[] = [];
    while (i < length) {
      const bsonSize = dv.getUint32(i, true);
      documents.push(new BSONBuffer(view(buf, length, i, bsonSize)));
      i += bsonSize;
    }

    return {
      msg: new this({
        flags,
        cursorId,
        startingFrom,
        numberReturned,
        documents
      }),
      readBytes: i
    };
  }
}

class OpUnknown {
  opCode = 'OP_UNKNOWN' as const;
  actualOpCode: number;
  body: Uint8Array;

  constructor(values: Pick<OpUnknown, 'actualOpCode' | 'body'>) {
    this.actualOpCode = values.actualOpCode;
    this.body = values.body;
  }
}

async function ReadOpContents(
  opcode: number,
  data: Uint8Array,
  length: number,
  maxMessageSize: number
): Promise<{ msg: OpContents; readBytes: number }> {
  switch (opcode) {
    case OpCode.OP_MSG:
      return OpMsg.Read(data, length);
    case OpCode.OP_REPLY:
      return OpReply.Read(data, length);
    case OpCode.OP_UPDATE:
      return OpUpdate.Read(data, length);
    case OpCode.OP_INSERT:
      return OpInsert.Read(data, length);
    case OpCode.OP_QUERY:
      return OpQuery.Read(data, length);
    case OpCode.OP_GET_MORE:
      return OpGetMore.Read(data, length);
    case OpCode.OP_DELETE:
      return OpDelete.Read(data, length);
    case OpCode.OP_KILL_CURSORS:
      return OpKillCursors.Read(data, length);
    case OpCode.OP_COMPRESSED:
      return OpCompressed.Read(data, length, maxMessageSize);
    default: {
      return {
        msg: new OpUnknown({ actualOpCode: opcode, body: data.subarray(0, length) }),
        readBytes: length
      };
    }
  }
}

export class FullMessage {
  header: MessageHeader;
  contents: OpContents;

  constructor(header: MessageHeader, contents: OpContents) {
    this.header = header;
    this.contents = contents;
  }
}

// needBytes is the number of additional bytes required before parsing can continue.
// Messages longer than maxMessageSize, or that would decompress past it, are rejected
export async function ParseMessage(
  data: Uint8Array,
  maxMessageSize = MAX_MESSAGE_SIZE_BYTES
): Promise<{ msg: FullMessage; readBytes: number } | { needBytes: number }> {
  if (data.length < 16) {
    return { needBytes: 16 - data.length };
  }

  const { msg: header, readBytes: headerBytes } = await MessageHeader.Read(data);
  // A length below the header size would consume no bytes and re-parse the
  // same data forever; an unbounded one lets a peer exhaust memory
  if (header.messageLength < headerBytes || header.messageLength > maxMessageSize) {
    throw new RangeError(`Invalid message length ${header.messageLength}`);
  }
  if (header.messageLength > data.length) {
    return { needBytes: header.messageLength - data.length };
  }
  const contents = (
    await ReadOpContents(
      header.opCode,
      data.subarray(headerBytes, header.messageLength),
      header.messageLength - headerBytes,
      maxMessageSize
    )
  ).msg;
  return {
    msg: new FullMessage(header, contents),
    readBytes: header.messageLength
  };
}

export { OpCode };

export interface SaslCommandInfo {
  type: 'saslStart' | 'saslContinue' | null;
  mechanism?: string;
  payload?: Uint8Array;
  conversationId?: number;
  db?: string;
}

export function getSaslCommand(msg: FullMessage): SaslCommandInfo {
  if (msg.contents.opCode !== 'OP_MSG') {
    return { type: null };
  }

  const opMsg = msg.contents as OpMsg;
  const bodySection = opMsg.sections.find((s) => s.kind === 'Body') as OpMsgBodySection | undefined;
  if (!bodySection) {
    return { type: null };
  }

  const doc = bodySection.body.data;
  const db = doc.$db || 'admin';

  if (doc.saslStart === 1) {
    return {
      type: 'saslStart',
      mechanism: doc.mechanism,
      payload: doc.payload?._bsontype === 'Binary' ? doc.payload.value() : undefined,
      db
    };
  }

  if (doc.saslContinue === 1) {
    return {
      type: 'saslContinue',
      conversationId: doc.conversationId,
      payload: doc.payload?._bsontype === 'Binary' ? doc.payload.value() : undefined,
      db
    };
  }

  return { type: null };
}

export function getCommandDb(msg: FullMessage): string | null {
  if (msg.contents.opCode !== 'OP_MSG') {
    return null;
  }

  const opMsg = msg.contents as OpMsg;
  const bodySection = opMsg.sections.find((s) => s.kind === 'Body') as OpMsgBodySection | undefined;
  if (!bodySection) {
    return null;
  }

  return bodySection.body.data.$db || null;
}

export function getCommandBody(msg: FullMessage): Record<string, unknown> | null {
  if (msg.contents.opCode !== 'OP_MSG') {
    return null;
  }

  const opMsg = msg.contents as OpMsg;
  const bodySection = opMsg.sections.find((s) => s.kind === 'Body') as OpMsgBodySection | undefined;
  if (!bodySection) {
    return null;
  }

  return bodySection.body.data;
}

// The message's document sequences (OP_MSG kind 1 sections) by field name. Most drivers
// send the documents of an insert, update or delete this way instead of in the body
export function getDocumentSequences(msg: FullMessage): Record<string, Document[]> {
  const sequences: Record<string, Document[]> = {};
  if (msg.contents.opCode === 'OP_MSG') {
    for (const section of msg.contents.sections) {
      if (section.kind === 'DocumentSequence') {
        sequences[section.docSequenceId] = section.objects.map((object) => object.data);
      }
    }
  }
  return sequences;
}
