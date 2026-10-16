# Vector with the proxy's log shipping config baked in.
# Build: docker build -t mongodb-oidc-proxy-vector ops/vector
FROM timberio/vector:0.59.0-distroless-libc@sha256:54a7c01056e98305fce80545ace22779035747af9e89114508330fe94f829831

COPY vector.yaml /etc/vector/vector.yaml

# Vector no longer expands ${VAR} in config by default. The config only reads
# ES_ENDPOINT and ES_INDEX from the environment, neither of which is secret;
# the API key is read from /run/secrets/es_api_key
ENV VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true

# Run unprivileged: Vector only reads the proxy's log files (world-readable) and
# its secret, and writes its data directory. WORKDIR creates that directory owned
# by this user (the base image's /var/lib/vector is root-owned), and a new volume
# mounted there inherits the ownership
USER 65532:65532
WORKDIR /var/lib/vector/data

# Read checkpoints and the disk buffer; mount a named volume so they survive
# container replacement (otherwise logs are re-sent or lost)
VOLUME ["/var/lib/vector/data"]

CMD ["--config", "/etc/vector/vector.yaml"]
