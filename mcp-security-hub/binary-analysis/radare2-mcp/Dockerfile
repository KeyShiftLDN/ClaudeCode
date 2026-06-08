# Radare2 MCP Server
# Wrapper around official radareorg/radare2-mcp
# https://github.com/radareorg/radare2-mcp

FROM alpine:3.19 AS builder

RUN apk add --no-cache \
    git \
    build-base \
    meson \
    ninja \
    pkgconfig \
    linux-headers \
    python3

# Clone and build radare2 with proper prefix install
RUN git clone --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2 && \
    cd /tmp/radare2 && \
    meson setup build --prefix=/opt/radare2 --buildtype=release && \
    ninja -C build && \
    ninja -C build install

# Set up environment for r2pm
ENV PATH="/opt/radare2/bin:$PATH"
ENV PKG_CONFIG_PATH="/opt/radare2/lib/pkgconfig"
ENV LD_LIBRARY_PATH="/opt/radare2/lib"
ENV R2_LIBDIR="/opt/radare2/lib"

# Verify radare2 works
RUN r2 -v

# Install r2mcp via r2pm
RUN r2pm -Uci r2mcp

FROM alpine:3.19

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="Radare2 MCP Server - Official radareorg/radare2-mcp"
LABEL org.opencontainers.image.licenses="MIT"
LABEL upstream.repo="https://github.com/radareorg/radare2-mcp"

# Security: Create non-root user
RUN addgroup -g 1000 mcpuser && \
    adduser -D -u 1000 -G mcpuser mcpuser

RUN apk add --no-cache \
    ca-certificates \
    tini \
    libgcc \
    libstdc++

# Copy radare2 installation from builder
COPY --from=builder /opt/radare2 /opt/radare2
COPY --from=builder /root/.local/share/radare2 /home/mcpuser/.local/share/radare2

# Set up user environment
RUN chown -R mcpuser:mcpuser /home/mcpuser

WORKDIR /home/mcpuser

USER mcpuser

# Sample binaries directory
RUN mkdir -p /home/mcpuser/samples

ENV PATH="/home/mcpuser/.local/share/radare2/prefix/bin:/opt/radare2/bin:$PATH"
ENV LD_LIBRARY_PATH="/opt/radare2/lib"
ENV R2_LIBDIR="/opt/radare2/lib"

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD r2 -v > /dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["r2mcp"]
