# Dawr: one container, one volume (/data). Build from the repository root:
#
#   docker build -f deploy/Dockerfile -t dawr:0.1.0 .
#
# The image runs as the unprivileged `node` user, never writes outside /data
# (run it with a read-only root filesystem: deploy/compose.yml does), and
# makes no outbound connection. NODE_IMAGE may name a mirror of the same
# image, e.g. --build-arg NODE_IMAGE=mirror.gcr.io/library/node:22-bookworm-slim

ARG NODE_IMAGE=node:22-bookworm-slim

# ---- 1. build: every dependency, compile the server, bundle the client ----
FROM ${NODE_IMAGE} AS build
WORKDIR /src
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    npm_config_audit=false \
    npm_config_fund=false \
    npm_config_update_notifier=false
COPY package.json package-lock.json ./
RUN npm ci --loglevel=error
COPY tsconfig.json vite.config.ts ./
COPY shared ./shared
COPY server ./server
COPY client ./client
RUN npm run build && npm prune --omit=dev --loglevel=error

# ---- 2. runtime: production dependencies and the build output only ----
FROM ${NODE_IMAGE}
LABEL org.opencontainers.image.title="Dawr" \
      org.opencontainers.image.description="Transparent, verifiable savings circles. Records money; never moves it." \
      org.opencontainers.image.source="https://github.com/omanras/raqib" \
      org.opencontainers.image.licenses="MIT"
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DATA_DIR=/data \
    CLIENT_DIR=/app/client/dist
# SESSION_SECRET, BASE_URL and TRUST_PROXY=1 come from the operator: the
# server refuses to start in production without them (docs/OPERATIONS.md).
WORKDIR /app
# Code and dependencies belong to root and are not writable by the app user.
COPY --from=build /src/package.json /src/package-lock.json ./
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/server/dist ./server/dist
COPY --from=build /src/client/dist ./client/dist
COPY deploy/dbtool.mjs deploy/healthcheck.mjs ./deploy/
RUN mkdir -p /data && chown node:node /data && chmod 0700 /data
USER node
VOLUME ["/data"]
EXPOSE 3000
# Healthy when GET /api/health on the local port says ok with the database ok.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "/app/deploy/healthcheck.mjs"]
CMD ["node", "server/dist/server/main.js"]
