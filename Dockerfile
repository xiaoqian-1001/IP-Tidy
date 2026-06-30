FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY cf-scanner-src/ .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o cf-scanner main.go

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential libpcap-dev iprange \
    python3 curl iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/masscan
RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan . \
    && make -j"$(nproc)" \
    && cp bin/masscan /usr/local/bin/ \
    && rm -rf /tmp/masscan

WORKDIR /opt/IP-Tidy
COPY . .
COPY --from=builder /src/cf-scanner ./cf-scanner
RUN chmod +x cf-scanner

RUN mkdir -p /root/.config/ip-tidy && \
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/arm64/arm64/') && \
    CFST_URL="https://github.com/XIU2/CloudflareSpeedTest/releases/latest/download/cfst_linux_${ARCH}.tar.gz" && \
    curl -fsSL -o /tmp/cfst.tar.gz "$CFST_URL" && \
    tar -xzf /tmp/cfst.tar.gz -C /root/.config/ip-tidy/ cfst && \
    chmod +x /root/.config/ip-tidy/cfst && \
    rm -f /tmp/cfst.tar.gz

HEALTHCHECK --interval=30s --timeout=5s --retries=2 CMD pgrep -f "python3 run.py" || exit 1
ENTRYPOINT ["python3", "run.py"]
