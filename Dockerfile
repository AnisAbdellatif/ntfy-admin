# syntax=docker/dockerfile:1
# Cross-compiles on the build host, so multi-arch builds need no emulation.
# Base images are pinned by digest (updated by Dependabot).
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ntfy-admin ./cmd/ntfy-admin

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ntfy-admin /ntfy-admin
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/ntfy-admin", "healthcheck"]
ENTRYPOINT ["/ntfy-admin"]
