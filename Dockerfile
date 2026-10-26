FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build
RUN apk add --no-cache ca-certificates
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /xhttp-splitter .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /xhttp-splitter /xhttp-splitter
LABEL org.opencontainers.image.title="xhttp-splitter" \
      org.opencontainers.image.description="Local HTTP/1.1 -> TLS splitter that keeps an Xray xhttp (packet-up) tunnel alive against SNI-based DPI throttling." \
      org.opencontainers.image.source="https://github.com/freedomproto/xhttp-splitter" \
      org.opencontainers.image.url="https://github.com/freedomproto/xhttp-splitter" \
      org.opencontainers.image.licenses="MIT"
ENV XHTTP_LISTEN=0.0.0.0:10443
EXPOSE 10443
ENTRYPOINT ["/xhttp-splitter"]
