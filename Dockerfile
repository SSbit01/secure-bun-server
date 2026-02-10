# ---- Build Stage ----
FROM oven/bun:1-alpine AS builder

# Set working directory
WORKDIR /app

# Copy ONLY dependency files first
COPY package.json bun.lockb* ./

# Install deps (this layer is cached unless package files change)
RUN bun install --frozen-lockfile

# NOW copy the rest (source code)
COPY . .

# Build (only re-runs if source code or deps changed)
RUN bun run build


# ---- Runtime Stage ----
FROM oven/bun:1-alpine

# Set working directory
WORKDIR /app

# Copy built dist files from builder
COPY --from=builder /app/dist ./dist

# Expose the port your server runs on (default 3000)
EXPOSE 3000

# Start the server with Bun
CMD ["bun", "./dist/index.js"]