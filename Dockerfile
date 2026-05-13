FROM python:3.11-slim AS scannerctl-fetcher

ARG TARGETARCH
ARG SCANNERCTL_VERSION=v23.45.1
ARG SCANNERCTL_X86_64_SHA256=f1df9911f226947fb135f32d1f20bd3d825f47c8098ed61dd241277443021be3
ARG SCANNERCTL_AARCH64_SHA256=556d1e2c24c81c96a9aaada81db642422d5193142bb503368a994f72d86a1379

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) asset="scannerctl-x86_64-unknown-linux-gnu"; sha256="$SCANNERCTL_X86_64_SHA256" ;; \
      arm64) asset="scannerctl-aarch64-unknown-linux-gnu"; sha256="$SCANNERCTL_AARCH64_SHA256" ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/greenbone/openvas-scanner/releases/download/${SCANNERCTL_VERSION}/${asset}"; \
    curl -fsSL "$url" -o /usr/local/bin/scannerctl; \
    echo "$sha256  /usr/local/bin/scannerctl" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/scannerctl

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=scannerctl-fetcher /usr/local/bin/scannerctl /usr/local/bin/scannerctl
COPY --from=ghcr.io/astral-sh/uv:0.11.3 /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md scan-docs.md ./
COPY scanconfigs ./scanconfigs
COPY src ./src

RUN uv sync --locked --no-dev --no-editable

ENTRYPOINT ["openvas-example"]
CMD ["--help"]
