# The echo box (cmd/dromas-echo): a client on a published address that
# answers every message passing every check with a signed reply carrying
# the body back, with the dromas command beside it for the operator (addr,
# adopt). How it runs, its state in a tmpfs and its identity key mounted in:
# cmd/dromas-echo.
#
# The Go stage runs on the builder's own platform and cross-compiles for the
# target's (docker build --platform linux/amd64,linux/arm64), so no stage
# runs under emulation: the image it is copied into only copies.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/ ./cmd/dromas-echo ./cmd/dromas

# Debian slim. Each base image is an exact tag and its index digest, which
# Dependabot moves together.
# Nothing runs in it but the binaries, as uid 65532; the CA bundle comes from
# the build stage, for TLS to the server.
FROM debian:13.7-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/dromas-echo /out/dromas /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["dromas-echo"]
