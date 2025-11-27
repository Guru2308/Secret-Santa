# Build stage
FROM golang:1.23.3-bookworm AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o secret-santa .

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/secret-santa .

# Copy static files and other resources
COPY --from=builder /app/static ./static
COPY --from=builder /app/users.csv ./users.csv
COPY --from=builder /app/credentials.json ./credentials.json

EXPOSE 8080

CMD ["./secret-santa"]
