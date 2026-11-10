# Static build of the console, served by nginx.
FROM node:26-bookworm-slim AS build
WORKDIR /app
COPY packages ./packages
COPY apps/console ./apps/console
ARG VITE_SBC_CONTRACT=""
ARG VITE_SBC_RELAY=""
ENV VITE_SBC_CONTRACT=$VITE_SBC_CONTRACT VITE_SBC_RELAY=$VITE_SBC_RELAY
RUN cd apps/console && npm ci --no-audit --no-fund && npm run build

FROM nginx:1.29-alpine
COPY --from=build /app/apps/console/dist /usr/share/nginx/html
