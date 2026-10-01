# ParleyPort keeps no state except, in domain mode, its Let's Encrypt
# certificates, so the only volume is the certificate cache.

FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
# .dockerignore keeps .git out, so -version knows the commit only from here.
ARG COMMIT=
RUN CGO_ENABLED=0 go build \
      -ldflags="-s -w -X github.com/junkerderprovinz/parleyport/internal/buildinfo.Version=${VERSION} -X github.com/junkerderprovinz/parleyport/internal/buildinfo.Commit=${COMMIT}" \
      -o /out/parleyport ./cmd/parleyport

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
# 99:100 is nobody:users on Unraid, the owner of everything under appdata, so
# the certificate cache stays writable without a chown.
RUN apk add --no-cache ca-certificates \
 && adduser -D -H -u 99 -G users parley \
 && mkdir -p /var/lib/parleyport/certs \
 && chown -R 99:100 /var/lib/parleyport
COPY --from=build /out/parleyport /usr/local/bin/parleyport

# Plain HTTP on 8760, or TLS on 443 once PARLEYPORT_DOMAIN is set. The TLS
# listener only answers its own domain, so there the health check settles for
# the port being open.
EXPOSE 8760 443
VOLUME /var/lib/parleyport

USER 99:100
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8760/health >/dev/null 2>&1 || nc -z 127.0.0.1 443 || exit 1
ENTRYPOINT ["/usr/local/bin/parleyport"]
