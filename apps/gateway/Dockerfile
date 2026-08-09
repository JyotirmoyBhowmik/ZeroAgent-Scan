FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY apps/gateway/go.mod apps/gateway/go.sum* ./
RUN go mod download

COPY apps/gateway/ .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/bin/gateway ./cmd/gateway

FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/bin/gateway /app/gateway

USER 65534:65534

ENTRYPOINT ["/app/gateway"]
