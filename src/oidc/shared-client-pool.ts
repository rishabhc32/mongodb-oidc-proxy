import type { MongoClient } from 'mongodb';

// A connection's hold on the backend client shared by all of a user's connections
export interface UserClientLease {
  readonly email: string;
  readonly client: MongoClient;
  release(): void;
}

interface PoolEntry {
  client: Promise<MongoClient>;
  refs: number;
}

// One backend client per user, shared by all of that user's connections.
// A client is created on first use and closed when its last lease is released
export class SharedClientPool {
  private readonly entries = new Map<string, PoolEntry>();

  // Leases the user's client, creating it with `create` if none exists. The lease
  // is counted before the client is ready, so concurrent callers share one creation
  async acquire(email: string, create: () => Promise<MongoClient>): Promise<UserClientLease> {
    let entry = this.entries.get(email);
    if (!entry) {
      entry = { client: create(), refs: 0 };
      this.entries.set(email, entry);
    }

    const acquired = entry;
    acquired.refs++;

    let client: MongoClient;
    try {
      client = await acquired.client;
    } catch (err) {
      // Forget the failed client so the next acquire creates a new one
      if (this.entries.get(email) === acquired) {
        this.entries.delete(email);
      }
      throw err;
    }

    let released = false;
    return {
      email,
      client,
      release: () => {
        if (released) {
          return;
        }
        released = true;
        if (--acquired.refs === 0) {
          if (this.entries.get(email) === acquired) {
            this.entries.delete(email);
          }
          client.close().catch(() => {});
        }
      }
    };
  }

  // Leases held or pending for the user
  connectionCount(email: string): number {
    return this.entries.get(email)?.refs ?? 0;
  }

  async closeAll(): Promise<void> {
    const closing = [...this.entries.values()].map((entry) => entry.client.then((client) => client.close()));
    this.entries.clear();
    await Promise.allSettled(closing);
  }
}
