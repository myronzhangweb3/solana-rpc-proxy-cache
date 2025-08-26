FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o solana-proxy .

FROM alpine:3.19

WORKDIR /app

COPY --from=builder /app/solana-proxy /app/

EXPOSE 8080

CMD ["./solana-proxy"]
