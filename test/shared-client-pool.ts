import assert from 'assert';
import sinon from 'sinon';
import type { MongoClient } from 'mongodb';
import { SharedClientPool } from '@src/oidc/shared-client-pool';

function fakeClient(): MongoClient & { close: sinon.SinonStub } {
  return { close: sinon.stub().resolves() } as any;
}

describe('SharedClientPool', () => {
  it('shares one client between concurrent acquires of the same user', async () => {
    const pool = new SharedClientPool();
    const client = fakeClient();
    const create = sinon.stub().resolves(client);

    const [a, b] = await Promise.all([pool.acquire('alice', create), pool.acquire('alice', create)]);

    assert.strictEqual(create.callCount, 1);
    assert.strictEqual(a.client, client);
    assert.strictEqual(b.client, client);
    assert.strictEqual(pool.connectionCount('alice'), 2);
  });

  it('keeps separate clients per user', async () => {
    const pool = new SharedClientPool();
    const alice = await pool.acquire('alice', async () => fakeClient());
    const bob = await pool.acquire('bob', async () => fakeClient());

    assert.notStrictEqual(alice.client, bob.client);
    assert.strictEqual(pool.connectionCount('alice'), 1);
    assert.strictEqual(pool.connectionCount('bob'), 1);
  });

  it('closes the client only when the last lease is released', async () => {
    const pool = new SharedClientPool();
    const client = fakeClient();
    const a = await pool.acquire('alice', async () => client);
    const b = await pool.acquire('alice', async () => client);

    a.release();
    assert(client.close.notCalled);
    assert.strictEqual(pool.connectionCount('alice'), 1);

    b.release();
    assert(client.close.calledOnce);
    assert.strictEqual(pool.connectionCount('alice'), 0);
  });

  it('ignores repeated releases of the same lease', async () => {
    const pool = new SharedClientPool();
    const client = fakeClient();
    const a = await pool.acquire('alice', async () => client);
    const b = await pool.acquire('alice', async () => client);

    a.release();
    a.release();
    assert(client.close.notCalled);
    assert.strictEqual(pool.connectionCount('alice'), 1);
    b.release();
    assert(client.close.calledOnce);
  });

  it('creates a new client after the previous one was closed', async () => {
    const pool = new SharedClientPool();
    const first = fakeClient();
    const second = fakeClient();

    (await pool.acquire('alice', async () => first)).release();
    const lease = await pool.acquire('alice', async () => second);

    assert.strictEqual(lease.client, second);
  });

  it('rejects every waiter when creation fails, and retries on the next acquire', async () => {
    const pool = new SharedClientPool();
    const create = sinon.stub().rejects(new Error('backend unavailable'));

    const results = await Promise.allSettled([pool.acquire('alice', create), pool.acquire('alice', create)]);
    assert.deepStrictEqual(
      results.map((r) => r.status),
      ['rejected', 'rejected']
    );
    assert.strictEqual(create.callCount, 1);
    assert.strictEqual(pool.connectionCount('alice'), 0);

    const client = fakeClient();
    const lease = await pool.acquire('alice', async () => client);
    assert.strictEqual(lease.client, client);
  });

  it('closes every client on closeAll', async () => {
    const pool = new SharedClientPool();
    const alice = fakeClient();
    const bob = fakeClient();
    await pool.acquire('alice', async () => alice);
    await pool.acquire('bob', async () => bob);

    await pool.closeAll();

    assert(alice.close.calledOnce);
    assert(bob.close.calledOnce);
    assert.strictEqual(pool.connectionCount('alice'), 0);
  });
});
