# syntax=docker/dockerfile:1.7
# ReconX, the Argus recon engine, as an internal service (build context: repo root).
# Its web server has no user accounts, so it is never published: only the Argus API
# reaches it, on the compose network, after its own sign-in, roles and audit.

# ── build: a static binary (pure-Go SQLite, no cgo) ──────────────────────────
FROM golang:1.25.0-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/reconx ./cmd/reconx

# ── runtime: nmap for authorised active scans; no browser (capture is off) ────
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 recon \
 && useradd --system --uid 10001 --gid recon --home-dir /data --shell /usr/sbin/nologin recon \
 && mkdir -p /data/config && chown -R recon:recon /data
COPY --from=build /out/reconx /usr/local/bin/reconx
# reports/, reports/monitor/ and cache/ are relative to the working directory;
# keys live under XDG_CONFIG_HOME. All of it is on the /data volume.
WORKDIR /data
ENV XDG_CONFIG_HOME=/data/config HOME=/data
USER recon
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["curl", "-fsS", "-o", "/dev/null", "http://127.0.0.1:8787/api/config"]
ENTRYPOINT ["reconx"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8787", "--no-open"]
