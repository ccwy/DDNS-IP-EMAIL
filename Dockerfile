# 编译阶段([M9] 升级至 golang:1.23-alpine,Go 1.22 已 EOL)
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ddns-notifier main.go

# 运行阶段([M9] 固定 alpine:3.20,避免 latest 标签漂移带来不可控变更)
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/ddns-notifier .
COPY templates/ ./templates/

# [H7] 以非 root 用户运行,降低容器逃逸与文件篡改风险
# 提前创建 /data 并授权,确保匿名卷场景下 appuser 可写配置
RUN adduser -D -u 1000 appuser && mkdir -p /data && chown -R appuser:appuser /app /data
USER appuser

EXPOSE 49809
VOLUME ["/data"]

CMD ["./ddns-notifier"]