FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cargo \
        git \
        libpcap-dev \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone --depth 1 https://github.com/greenbone/openvas-scanner.git /tmp/openvas-scanner \
    && cargo install --locked --path /tmp/openvas-scanner/rust/src/scannerctl --root /usr/local \
    && rm -rf /tmp/openvas-scanner /root/.cargo/registry /root/.cargo/git

COPY pyproject.toml README.md scan-docs.md ./
COPY src ./src

RUN pip install --no-cache-dir .

ENTRYPOINT ["openvas-example"]
CMD ["--help"]
