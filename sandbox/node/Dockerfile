# Node services (relay, demo agent, sudoctl, MCP server). Node runs the
# TypeScript sources directly (type stripping). The only runtime npm
# dependency is the Anthropic SDK, used by the demo agent's model act.
FROM node:26-bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY apps/relay ./apps/relay
COPY apps/demo-agent ./apps/demo-agent
COPY apps/sudoctl ./apps/sudoctl
COPY apps/sbc-mcp ./apps/sbc-mcp
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
ENV NODE_NO_WARNINGS=1 SBC_HOME=/state
# /data is the relay's database volume (compose); a fresh named volume takes
# the ownership of the image directory it is mounted on.
RUN mkdir -p /state /data && chown node:node /state /data
VOLUME ["/state"]
USER node
