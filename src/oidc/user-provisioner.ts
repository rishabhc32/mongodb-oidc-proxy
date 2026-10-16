import type { MongoClient } from 'mongodb';

// A connection's hold on the backend client shared by all of a user's connections
export interface UserClientLease {
  readonly email: string;
  readonly client: MongoClient;
  release(): void;
}

export type ProvisionResult = { lease: UserClientLease } | { error: string };

// Authorizes a user and leases their backend client. `current` is the lease the
// calling connection already holds, if any
export interface UserProvisioner {
  provisionUser(email: string, current: UserClientLease | undefined, debug: (message: string) => void): Promise<ProvisionResult>;
}
