# mongodb-oidc-proxy

OIDC-aware logging MongoDB wire protocol proxy.

**Transparent proxy mode (default):**
```shell
mongodb-wp-proxy [--ndjson] <remotehost:remoteport> <[localhost:]localport>
```

**OIDC proxy mode:**
```shell
mongodb-wp-proxy [--ndjson] [--tag <value>]... --oidc-mode --issuer <url> --client-id <id> --connection-string <uri> [--jwks-uri <url>] [--audience <aud>] [--max-connections-per-user <n>] <[localhost:]localport>
```

The `--tag` option can be specified multiple times to add multiple tags to log entries:
```shell
mongodb-wp-proxy --tag prod --tag us-east-1 --oidc-mode ...
```

The connection string can also be passed in the `MONGO_CONNECTION_STRING` environment variable, which keeps the credentials out of the process list.

### Authentication and authorization

A client logs in with the `MONGODB-OIDC` mechanism. The proxy accepts its token only if:

- it is signed by the issuer's keys and carries `iss` (matching `--issuer`), `exp`, and `client_id` (matching `--client-id`), plus `aud` when `--audience` is set
- its `email` claim is a plain email address, and `email_verified` is not `false` (tokens without `email_verified` are accepted)

The email is then authorized against MongoDB:

- a role named exactly after the email must exist in the `admin` database; built-in roles are never granted
- the proxy logs the user in as a MongoDB user of the same name with that single role, creating it with a random password if needed. It never takes over a user it did not create: users it creates are marked with `customData: { managedBy: "mongodb-oidc-proxy" }`, and an existing user without that mark is rejected unless its only role is the email role

The backend connection string needs a user that can run `rolesInfo`, `usersInfo`, `createUser` and `updateUser` on `admin` (for example `userAdminAnyDatabase`).

All of a user's connections share one backend client. `--max-connections-per-user` caps how many authenticated connections one user may hold (default: unlimited).

### Logging

With `--ndjson`, every forwarded command is logged with its user, database, command name and full request (and the response at `--log-level debug`). The `pwd` field of `createUser`/`updateUser` commands is replaced with `[REDACTED]`.

## LICENSE

Apache-2.0
