FROM golang:1.22-alpine AS build

WORKDIR /src
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/server ./cmd/server

FROM alpine:3.21

RUN apk add --no-cache ca-certificates wget openssl openvpn

WORKDIR /app
COPY --from=build /out/server /app/server
COPY prisma ./prisma

ENV PRISMA_MIGRATIONS_DIR=/app/prisma/migrations

EXPOSE 8080
ENTRYPOINT ["/app/server"]
