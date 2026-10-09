# syntax=docker/dockerfile:1
# Cross-compiles on the build host, so multi-arch builds need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ntfy-admin ./cmd/ntfy-admin

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ntfy-admin /ntfy-admin
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/ntfy-admin", "healthcheck"]
ENTRYPOINT ["/ntfy-admin"]
