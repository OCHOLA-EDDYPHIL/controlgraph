FROM node:22-bookworm@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a AS build

WORKDIR /web
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html tsconfig.json tsconfig.build.json tsconfig.node.json vite.config.ts ./
COPY src ./src
RUN npm run build:image

FROM node:22-bookworm@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a AS runtime

ENV NODE_ENV=production \
    PORT=8080

WORKDIR /app
COPY --from=build /web/dist ./dist
COPY host.mjs ./host.mjs

USER node
EXPOSE 8080
CMD ["node", "host.mjs"]
