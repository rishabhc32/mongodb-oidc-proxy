# mongodb-oidc-proxy

OIDC-aware logging MongoDB wire protocol proxy.

**Transparent proxy mode (default):**
```js
$ mongodb-wp-proxy [--ndjson] <remotehost:remoteport> <[localhost:]localport>
```

**OIDC proxy mode:**
```js
$ mongodb-wp-proxy [--ndjson] --oidc-mode --issuer <url> --client-id <id> --connection-string <uri> [--jwks-uri <url>] [--audience <aud>] <[localhost:]localport>
```

## LICENSE

Apache-2.0
