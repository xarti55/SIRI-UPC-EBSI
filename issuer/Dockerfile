FROM golang:1.23 as builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go get github.com/lib/pq
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM gcr.io/distroless/static

EXPOSE 8080

COPY --from=builder /app/main /

ENTRYPOINT ["/main"]
