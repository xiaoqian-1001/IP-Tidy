FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential libpcap-dev \
    iprange python3 python3-pip curl iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/masscan
RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan . \
    && make -j"$(nproc)" \
    && cp bin/masscan /usr/local/bin/ \
    && rm -rf /tmp/masscan

WORKDIR /opt/ASNIPtest
COPY . .

RUN chmod +x cf-scanner 2>/dev/null; true

ENTRYPOINT ["python3", "run.py"]
