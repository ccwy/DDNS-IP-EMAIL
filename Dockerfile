# 编译阶段
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ddns-notifier main.go

# 运行阶段
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/ddns-notifier .
COPY templates/ ./templates/

EXPOSE 8080
VOLUME ["/data"]

CMD ["./ddns-notifier"]