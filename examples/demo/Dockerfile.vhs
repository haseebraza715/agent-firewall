FROM node:20-bookworm-slim AS node

FROM ghcr.io/charmbracelet/vhs:latest

COPY --from=node /usr/local/ /usr/local/
RUN npx -y @modelcontextprotocol/server-filesystem /tmp </dev/null

WORKDIR /work
