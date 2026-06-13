FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/flowproxy ./cmd/flowproxy

FROM alpine:3.21
RUN adduser -D -h /app app
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/flowproxy /usr/local/bin/flowproxy
USER app
EXPOSE 80 443 9000
ENV DATA_FILE=/data/sites.json
ENV SETTINGS_FILE=/data/settings.json
ENV CERT_DATA_FILE=/data/certificates.json
ENV CERT_DIR=/data/certs
ENV ADMIN_ADDR=0.0.0.0:9000
ENV HTTP_ADDR=:80
ENV HTTPS_ADDR=:443
ENV ENABLE_AUTO_TLS=true
ENTRYPOINT ["flowproxy"]
