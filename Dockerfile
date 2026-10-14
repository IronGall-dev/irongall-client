# irongall-revocation-server, the reference revocation server (PROTOCOL.md
# §6.3): a static binary on Debian slim, built from this repository alone.
#
#   docker build -t irongall-revocation-server .
#   docker run -v <a directory uid 65532 can write>:/data irongall-revocation-server --dir /data --listen 0.0.0.0:8080
FROM golang:1.27.2-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /irongall-revocation-server ./cmd/irongall-revocation-server

# Debian slim, an exact tag, so a check for base-image updates can follow it.
# Nothing runs in it but the binary, as uid 65532. It makes no call out, so
# it carries no CA bundle.
FROM debian:13.7-slim
COPY --from=build /irongall-revocation-server /usr/local/bin/irongall-revocation-server
USER 65532:65532
ENTRYPOINT ["irongall-revocation-server"]
