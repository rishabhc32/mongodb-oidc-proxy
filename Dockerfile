# MongoDB OIDC proxy.
# Build: docker build -t mongodb-oidc-proxy .
FROM node:24-trixie-slim@sha256:7f486cabe892bff8fef04c0f7da8dba84a560be3e4e2740b7a86afc57ebec315 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run compile-ts && npm prune --omit=dev

FROM node:24-trixie-slim@sha256:7f486cabe892bff8fef04c0f7da8dba84a560be3e4e2740b7a86afc57ebec315
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/lib ./lib
COPY bin ./bin

# Log directory for --log-file, owned by the runtime user so a volume mounted
# here is writable and can be shared read-only with the Vector container
RUN mkdir -p /var/log/mongodb-wp-proxy && chown node:node /var/log/mongodb-wp-proxy

USER node
EXPOSE 27018
ENTRYPOINT ["node", "bin/mongodb-wp-proxy.js"]
CMD ["--help"]
