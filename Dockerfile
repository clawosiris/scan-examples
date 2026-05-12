FROM rust:1.88-bookworm AS scannerctl-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        libpcap-dev \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/greenbone/openvas-scanner.git /tmp/openvas-scanner \
    && cargo install --locked --path /tmp/openvas-scanner/rust --bin scannerctl --root /usr/local \
    && rm -rf /tmp/openvas-scanner /usr/local/.crates.toml /usr/local/.crates2.json /usr/local/cargo/registry

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=scannerctl-builder /usr/local/bin/scannerctl /usr/local/bin/scannerctl
COPY pyproject.toml README.md scan-docs.md ./
COPY src ./src

RUN pip install --no-cache-dir .

ENTRYPOINT ["openvas-example"]
CMD ["--help"]
