# Node services (relay, demo agent, sudoctl, MCP server). No npm runtime
# dependencies: Node runs the TypeScript sources directly (type stripping).
FROM node:26-bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
COPY packages ./packages
COPY apps/relay ./apps/relay
COPY apps/demo-agent ./apps/demo-agent
COPY apps/sudoctl ./apps/sudoctl
COPY apps/sbc-mcp ./apps/sbc-mcp
ENV NODE_NO_WARNINGS=1 SBC_HOME=/state
# /data is the relay's database volume (compose); a fresh named volume takes
# the ownership of the image directory it is mounted on.
RUN mkdir -p /state /data && chown node:node /state /data
VOLUME ["/state"]
USER node
