FROM golang:1.25 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -v -trimpath -ldflags '-d -w -s'

FROM scratch
ARG REVISION
LABEL org.opencontainers.image.title="Tor Onion Service vanity address generator"
LABEL org.opencontainers.image.description="Generates Tor Onion Service keypairs with a specified address prefix using an optimized search algorithm"
LABEL org.opencontainers.image.url="https://github.com/offset/onion-vanity-address"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"
LABEL org.opencontainers.image.revision="${REVISION}"

COPY --from=builder /app/onion-vanity-address /onion-vanity-address

ENTRYPOINT ["/onion-vanity-address"]
