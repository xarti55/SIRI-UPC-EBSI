# Start from the official Go image
FROM golang:1.23 as builder

WORKDIR /app

# Copy go.mod and go.sum first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Now fetch dependencies your code needs
RUN go get github.com/lib/pq
RUN go mod tidy

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final minimal image
FROM gcr.io/distroless/static

EXPOSE 8080

COPY --from=builder /app/main /

ENTRYPOINT ["/main"]
