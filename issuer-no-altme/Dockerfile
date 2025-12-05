FROM golang:1.25 AS builder
ENV GOTOOLCHAIN=auto

WORKDIR /app

# Copy modules first
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Optional check
RUN ls -la cert.pem key.pem || true

# Build app
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM gcr.io/distroless/static
WORKDIR /
COPY --from=builder /app/main /
COPY --from=builder /app/cert.pem /
COPY --from=builder /app/key.pem /
EXPOSE 7531
ENTRYPOINT ["/main"]
