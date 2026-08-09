FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY apps/api/go.mod apps/api/go.sum* ./
RUN go mod download

COPY apps/api/ .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/bin/server ./cmd/server

# Minimal distroless/scratch runtime
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/bin/server /app/server

EXPOSE 8080

USER 65534:65534

ENTRYPOINT ["/app/server"]
