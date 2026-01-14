import { randomBytes as cryptoRandomBytes } from 'crypto';

export const randomBytes = (size: number): Buffer => cryptoRandomBytes(size);
