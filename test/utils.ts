import assert from 'assert';
import { ksuid } from '@src/utils/ksuid';

describe('ksuid', function() {
  it('returns a 27-character string', () => {
    const id = ksuid();
    assert.strictEqual(id.length, 27);
    assert.strictEqual(typeof id, 'string');
  });

  it('uses only base62 characters', () => {
    const id = ksuid();
    assert.match(id, /^[0-9A-Za-z]+$/);
  });

  it('generates unique IDs', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      ids.add(ksuid());
    }
    assert.strictEqual(ids.size, 1000);
  });

  it('generates IDs that sort chronologically', async () => {
    const id1 = ksuid();
    await new Promise(resolve => setTimeout(resolve, 1100)); // Wait for timestamp to change
    const id2 = ksuid();
    assert(id1 < id2, `Expected ${id1} < ${id2}`);
  });

  it('generates IDs with consistent format across multiple calls', () => {
    for (let i = 0; i < 100; i++) {
      const id = ksuid();
      assert.strictEqual(id.length, 27);
      assert.match(id, /^[0-9A-Za-z]+$/);
    }
  });
});
