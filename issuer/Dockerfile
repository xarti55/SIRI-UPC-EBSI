FROM golang:1.24 as builder

WORKDIR /app

# Copy Go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy all source code and certs
COPY . .

# Ensure certs exist in builder
RUN ls -la cert.pem key.pem

# Build the Go app
RUN go get github.com/lib/pq
RUN go get github.com/vocdoni/davinci-node@main
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# -------------------------
# Final stage: distroless
# -------------------------
FROM gcr.io/distroless/static

# Set working dir (optional)
WORKDIR /

# Copy only necessary files
COPY --from=builder /app/main /
COPY --from=builder /app/cert.pem /
COPY --from=builder /app/key.pem /

EXPOSE 443

ENTRYPOINT ["/main"]
