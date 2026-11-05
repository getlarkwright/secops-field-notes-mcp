# Minimal image for clients that prefer to run the server in a container.
FROM node:22-alpine

LABEL io.modelcontextprotocol.server.name="io.github.getlarkwright/secops-field-notes-mcp"
LABEL org.opencontainers.image.source="https://github.com/getlarkwright/secops-field-notes-mcp"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src

# stdio transport: the client talks to the process over stdin/stdout.
ENTRYPOINT ["node", "src/index.js"]
