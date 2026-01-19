import { randomBytes } from 'crypto';

// KSUID: K-Sortable Unique Identifier
// 4 bytes timestamp (seconds since epoch offset) + 16 bytes random
// Base62 encoded to 27 characters

const EPOCH_OFFSET = 1400000000; // May 13, 2014 - KSUID epoch
const PAYLOAD_BYTES = 16;
const BASE62_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function base62Encode(bytes: Buffer): string {
  // Convert bytes to BigInt
  let num = BigInt(0);
  const shift = BigInt(8);
  const base = BigInt(62);
  for (const byte of bytes) {
    num = (num << shift) | BigInt(byte);
  }

  if (num === BigInt(0)) {
    return '0'.padStart(27, '0');
  }

  let result = '';
  while (num > BigInt(0)) {
    result = BASE62_CHARS[Number(num % base)] + result;
    num = num / base;
  }

  // Pad to 27 characters
  return result.padStart(27, '0');
}

export function ksuid(): string {
  const timestamp = Math.floor(Date.now() / 1000) - EPOCH_OFFSET;

  // Create 20-byte buffer: 4 bytes timestamp + 16 bytes random
  const buffer = Buffer.alloc(20);
  buffer.writeUInt32BE(timestamp, 0);
  randomBytes(PAYLOAD_BYTES).copy(buffer, 4);

  return base62Encode(buffer);
}
