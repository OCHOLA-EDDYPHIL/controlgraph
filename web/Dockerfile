FROM node:22-bookworm@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a AS build

WORKDIR /web
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html replay.html tsconfig.json tsconfig.build.json tsconfig.node.json vite.config.ts ./
COPY src ./src
RUN npm run build:image

FROM node:22-alpine3.22@sha256:cd7807368cf24826297cbad5dca1a44972ccfd770647db52a8c7589eb4599ac8 AS runtime

RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

ENV NODE_ENV=production \
    PORT=8080

WORKDIR /app
COPY --from=build /web/dist ./dist
COPY --chown=node:node --chmod=0444 host.mjs ./host.mjs

USER node
EXPOSE 8080
CMD ["node", "host.mjs"]
