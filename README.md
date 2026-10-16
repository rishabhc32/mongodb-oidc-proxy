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
- it has a string `email` claim, and `email_verified` is not `false` (tokens without `email_verified` are accepted)

The email is then authorized against MongoDB:

- a role named exactly after the email must exist in the `admin` database; built-in roles are never granted
- the proxy logs the user in as a MongoDB user of the same name with that single role, creating it with a random password if needed. It never takes over a user it did not create: users it creates are marked with `customData: { managedBy: "mongodb-oidc-proxy" }`, and an existing user without that mark is rejected

The backend connection string needs a user that can run `rolesInfo`, `usersInfo`, `createUser` and `updateUser` on `admin` (for example `userAdminAnyDatabase`).

All of a user's connections share one backend client. `--max-connections-per-user` caps how many authenticated connections one user may hold (default: unlimited).

### Compression

Clients can compress traffic to the proxy with zlib, for example `compressors=zlib` in the connection string. The proxy accepts compressed messages only after login, and compresses its reply to each compressed request. To compress traffic between the proxy and MongoDB, add `compressors=zlib` to the backend connection string.

### Logging

With `--ndjson`, every forwarded command is logged with its user, database, command name and full request (and the response at `--log-level debug`). The `pwd` field of `createUser`/`updateUser` commands is replaced with `[REDACTED]`.

## Running with Docker

Both images run as non-root users. Secrets are mounted as files, so they never appear in the container's environment or in `docker inspect`. Each secret file must be readable by the container's user.

### Proxy

```shell
docker build -t mongodb-oidc-proxy .

# The proxy runs as uid 1000
sudo chown 1000 /etc/mongodb-oidc-proxy/secrets/mongo_connection_string
sudo chmod 400 /etc/mongodb-oidc-proxy/secrets/mongo_connection_string

docker run -d --name mongodb-oidc-proxy \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -p 127.0.0.1:27018:27018 \
  -v proxy-logs:/var/log/mongodb-wp-proxy \
  -v /etc/mongodb-oidc-proxy/secrets/mongo_connection_string:/run/secrets/mongo_connection_string:ro \
  -e MONGO_CONNECTION_STRING_FILE=/run/secrets/mongo_connection_string \
  mongodb-oidc-proxy \
  --ndjson --oidc-mode --issuer <url> --client-id <id> \
  --log-file /var/log/mongodb-wp-proxy/proxy.log 0.0.0.0:27018
```

The proxy must listen on `0.0.0.0` inside the container, but it does not serve TLS. Publish the port on `127.0.0.1` (as above) or a private network only.

On `docker stop` (SIGTERM) or Ctrl+C (SIGINT), the proxy stops accepting connections and gives commands already received up to 5 seconds to finish. It then closes every connection, flushes the log and exits with code 0. A second signal exits immediately.

### Log shipping to Elasticsearch

[Vector](https://vector.dev) tails the proxy's log file from the shared volume and sends each event to Elasticsearch. The config is in `ops/vector/vector.yaml`. First run `setup-elasticsearch.sh` to create the ILM policy, index template and `mongo-logs` write alias. Then create an API key that can write to `mongo-logs*` (see `ops/elasticsearch-role.json`) and save its `encoded` value as the secret:

```shell
docker build -t mongodb-oidc-proxy-vector ops/vector

# Vector runs as uid 65532
sudo chown 65532 /etc/mongodb-oidc-proxy/secrets/es_api_key
sudo chmod 400 /etc/mongodb-oidc-proxy/secrets/es_api_key

docker run -d --name mongodb-oidc-proxy-vector \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -v proxy-logs:/var/log/mongodb-wp-proxy:ro \
  -v vector-data:/var/lib/vector/data \
  -v /etc/mongodb-oidc-proxy/secrets/es_api_key:/run/secrets/es_api_key:ro \
  -e ES_ENDPOINT=https://es.internal:9200 \
  mongodb-oidc-proxy-vector
```

- `vector-data` holds Vector's read checkpoints and its disk buffer. Keep this volume so restarts don't re-send logs, and so events queued during an Elasticsearch outage aren't lost.
- `ES_INDEX` overrides the write alias (default `mongo-logs`).
- The Elasticsearch certificate is verified against the image's CA bundle. For a private CA, mount a bundle that includes it and set `SSL_CERT_FILE` to its path.
- Import `ops/mongo-logs-kibana-dashboard.ndjson` into Kibana (Stack Management → Saved Objects).

The transform has unit tests: `vector test ops/vector/vector.yaml test/vector/normalize.test.yaml`.

## LICENSE

Apache-2.0
