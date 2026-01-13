import { serialize, Binary, Document } from 'bson';
import { OpCode } from '../parse';
import type { IdpInfo } from './types';

export class MessageBuilder {
  private requestIdCounter = 0;

  private nextRequestId(): number {
    return ++this.requestIdCounter;
  }

  private buildHeader(messageLength: number, responseTo: number): Buffer {
    const header = Buffer.alloc(16);
    header.writeInt32LE(messageLength, 0);
    header.writeInt32LE(this.nextRequestId(), 4);
    header.writeInt32LE(responseTo, 8);
    header.writeInt32LE(OpCode.OP_MSG, 12);
    return header;
  }

  buildOpMsg(responseTo: number, document: Document): Buffer {
    const bsonDoc = serialize(document);

    // OP_MSG format:
    // - flagBits: uint32 (4 bytes)
    // - section kind: uint8 (1 byte, 0 = body)
    // - BSON document

    const flagBits = Buffer.alloc(4);
    flagBits.writeUInt32LE(0, 0);

    const sectionKind = Buffer.alloc(1);
    sectionKind.writeUInt8(0, 0);

    const bodyLength = 4 + 1 + bsonDoc.length; // flagBits + kind + bson
    const messageLength = 16 + bodyLength; // header + body

    const header = this.buildHeader(messageLength, responseTo);

    return Buffer.concat([header, flagBits, sectionKind, bsonDoc]);
  }

  buildSaslStartResponse(responseTo: number, conversationId: number, idpInfo: IdpInfo): Buffer {
    // Serialize IdpInfo as BSON binary payload
    const idpInfoDoc: Document = {
      issuer: idpInfo.issuer,
      clientId: idpInfo.clientId
    };
    if (idpInfo.requestScopes) {
      idpInfoDoc.requestScopes = idpInfo.requestScopes;
    }
    const payloadBson = serialize(idpInfoDoc);

    const response: Document = {
      conversationId,
      done: false,
      payload: new Binary(payloadBson),
      ok: 1
    };

    return this.buildOpMsg(responseTo, response);
  }

  buildSaslContinueResponse(responseTo: number, conversationId: number, done: boolean): Buffer {
    const response: Document = {
      conversationId,
      done,
      payload: new Binary(Buffer.alloc(0)),
      ok: 1
    };

    return this.buildOpMsg(responseTo, response);
  }

  buildAuthSuccessResponse(responseTo: number, conversationId: number): Buffer {
    return this.buildSaslContinueResponse(responseTo, conversationId, true);
  }

  buildAuthFailureResponse(responseTo: number, errorMessage: string, code = 18): Buffer {
    const response: Document = {
      ok: 0,
      errmsg: errorMessage,
      code,
      codeName: code === 18 ? 'AuthenticationFailed' : 'UnknownError'
    };

    return this.buildOpMsg(responseTo, response);
  }

  buildCommandResponse(responseTo: number, result: Document): Buffer {
    // Ensure ok field is present
    if (result.ok === undefined) {
      result.ok = 1;
    }
    return this.buildOpMsg(responseTo, result);
  }

  buildErrorResponse(responseTo: number, errorMessage: string, code = 1): Buffer {
    const response: Document = {
      ok: 0,
      errmsg: errorMessage,
      code,
      codeName: 'InternalError'
    };

    return this.buildOpMsg(responseTo, response);
  }

  // Build legacy OP_REPLY for older drivers using OP_QUERY
  buildOpReply(responseTo: number, document: Document): Buffer {
    const bsonDoc = serialize(document);

    // OP_REPLY format (opcode 1):
    // - responseFlags: int32 (4 bytes)
    // - cursorID: int64 (8 bytes)
    // - startingFrom: int32 (4 bytes)
    // - numberReturned: int32 (4 bytes)
    // - documents: BSON[]

    const bodyLength = 4 + 8 + 4 + 4 + bsonDoc.length;
    const messageLength = 16 + bodyLength;

    const header = Buffer.alloc(16);
    header.writeInt32LE(messageLength, 0);
    header.writeInt32LE(this.nextRequestId(), 4);
    header.writeInt32LE(responseTo, 8);
    header.writeInt32LE(1, 12); // OP_REPLY = 1

    const body = Buffer.alloc(20);
    body.writeInt32LE(0, 0); // responseFlags
    body.writeBigInt64LE(BigInt(0), 4); // cursorID
    body.writeInt32LE(0, 12); // startingFrom
    body.writeInt32LE(1, 16); // numberReturned

    return Buffer.concat([header, body, bsonDoc]);
  }
}
