# Stage 1: Build
FROM debian:12-slim AS builder

# Install build dependencies
RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y build-essential libzmq3-dev cmake && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy necessary source files
COPY cmake/ ./cmake/
COPY src/ ./src/
COPY CMakeLists.txt .

# Build project
RUN mkdir out && cd out && cmake -DCMAKE_BUILD_TYPE=Release .. && make

# Stage 2: Final Image
FROM debian:12-slim AS asicseer

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libzmq5 \
    libgssapi-krb5-2 \
    libnorm1 \
    libpgm-5.3-0 \
    libsodium23 \
    libbsd0 \
    libk5crypto3 \
    libkrb5-3 \
    libkrb5support0 \
    libkeyutils1 \
    libssl3 \
    netcat-traditional && \
    rm -rf /var/lib/apt/lists/*

# Create default log directory
RUN mkdir -p /asicseer/logs

# Copy built binaries
COPY --from=builder /build/out/src/notifier /usr/bin/
COPY --from=builder /build/out/src/summariser /usr/bin/
COPY --from=builder /build/out/src/asicseer-* /usr/bin/

# Health check on port 3333
HEALTHCHECK --interval=60s --timeout=5s --retries=30 --start-period=30s \
  CMD ["nc", "-z", "localhost", "3333"]

# Default CMD
CMD ["/usr/bin/asicseer-pool", "-B", "-k", "-c", "/asicseer/conf/asicseer-pool.conf"]
