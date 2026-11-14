# Node 24, no native build tools needed (snarkjs is pure JS).
FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY src ./src
COPY circuits ./circuits
# data/ is the runtime state dir (seen-set, decision log, response cache).
# On fly.io it is backed by a 1 GB volume mounted at /data (see fly.toml).
RUN mkdir -p /data
ENV NODE_ENV=production PORT=8080 HOST=0.0.0.0 DATA_DIR=/data
EXPOSE 8080
CMD ["node", "src/server.js"]
