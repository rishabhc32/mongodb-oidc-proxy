import assert from 'assert';
import { ksuid } from '@src/utils/ksuid';
import { Singleflight } from '@src/utils/sync';

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

describe('Singleflight', function() {
  it('executes the function and returns the value', async () => {
    const sf = new Singleflight();
    const result = await sf.do('key1', async () => 'value1');
    assert.strictEqual(result.value, 'value1');
    assert.strictEqual(result.shared, false);
  });

  it('deduplicates concurrent calls with the same key', async () => {
    const sf = new Singleflight();
    let callCount = 0;

    const fn = async () => {
      callCount++;
      await new Promise(resolve => setImmediate(resolve));
      return 'result';
    };

    const [r1, r2, r3] = await Promise.all([
      sf.do('key', fn),
      sf.do('key', fn),
      sf.do('key', fn)
    ]);

    assert.strictEqual(callCount, 1, 'Function should only be called once');
    assert.strictEqual(r1.value, 'result');
    assert.strictEqual(r2.value, 'result');
    assert.strictEqual(r3.value, 'result');
    assert.strictEqual(r1.shared, true, 'First caller should see shared=true when others joined');
    assert.strictEqual(r2.shared, true);
    assert.strictEqual(r3.shared, true);
  });

  it('allows different keys to run concurrently', async () => {
    const sf = new Singleflight();
    let callCount = 0;

    const fn = async (val: string) => {
      callCount++;
      await new Promise(resolve => setImmediate(resolve));
      return val;
    };

    const [r1, r2] = await Promise.all([
      sf.do('key1', () => fn('a')),
      sf.do('key2', () => fn('b'))
    ]);

    assert.strictEqual(callCount, 2, 'Both functions should be called');
    assert.strictEqual(r1.value, 'a');
    assert.strictEqual(r2.value, 'b');
  });

  it('allows new calls after previous one completes', async () => {
    const sf = new Singleflight();
    let callCount = 0;

    const fn = async () => {
      callCount++;
      return callCount;
    };

    const r1 = await sf.do('key', fn);
    const r2 = await sf.do('key', fn);

    assert.strictEqual(callCount, 2, 'Function should be called twice');
    assert.strictEqual(r1.value, 1);
    assert.strictEqual(r2.value, 2);
    assert.strictEqual(r1.shared, false);
    assert.strictEqual(r2.shared, false);
  });

  it('propagates errors to all waiters', async () => {
    const sf = new Singleflight();
    const error = new Error('test error');

    const fn = async () => {
      await new Promise(resolve => setImmediate(resolve));
      throw error;
    };

    const results = await Promise.allSettled([
      sf.do('key', fn),
      sf.do('key', fn)
    ]);

    assert.strictEqual(results[0].status, 'rejected');
    assert.strictEqual(results[1].status, 'rejected');
    assert.strictEqual((results[0] as PromiseRejectedResult).reason, error);
    assert.strictEqual((results[1] as PromiseRejectedResult).reason, error);
  });

  it('forget removes inflight entry allowing new call', async () => {
    const sf = new Singleflight();
    let callCount = 0;
    let resolveFirst: () => void = () => {};

    const firstPromise = sf.do('key', async () => {
      callCount++;
      await new Promise<void>(resolve => { resolveFirst = resolve; });
      return 'first';
    });

    // Forget the key while first call is in progress
    sf.forget('key');

    // Start a new call - should run independently
    const secondPromise = sf.do('key', async () => {
      callCount++;
      return 'second';
    });

    const r2 = await secondPromise;
    assert.strictEqual(r2.value, 'second');
    assert.strictEqual(callCount, 2, 'Both functions should be called after forget');

    // Complete the first call
    resolveFirst();
    const r1 = await firstPromise;
    assert.strictEqual(r1.value, 'first');
  });
});
