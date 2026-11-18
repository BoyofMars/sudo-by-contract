# Node services (relay, demo agent, sudoctl, MCP server). Node runs the
# TypeScript sources directly (type stripping). The runtime npm dependencies
# are the demo agent's model act: the Anthropic and Google SDKs, and for NEAR
# AI Cloud, @phala/dcap-qvl-node (Intel TDX quote verification) and ethers.
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
# dcap-qvl ships its verifier as WebAssembly inside the npm package (no install
# script, no native build), so --ignore-scripts keeps it; prove it loads here.
RUN cd apps/demo-agent && node --input-type=module -e "const q = await import('@phala/dcap-qvl-node'); if (typeof q.js_verify !== 'function') throw new Error('dcap-qvl verifier missing'); await import('ethers')"
ENV NODE_NO_WARNINGS=1 SBC_HOME=/state
# /data is the relay's database volume (compose); a fresh named volume takes
# the ownership of the image directory it is mounted on.
RUN mkdir -p /state /data && chown node:node /state /data
VOLUME ["/state"]
USER node
