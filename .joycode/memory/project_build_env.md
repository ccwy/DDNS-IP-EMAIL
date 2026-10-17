---
name: DDNS-IP-EMAIL 构建环境
description: '本机无 Go/Docker，编译验证依赖 Docker/CI；项目用 Dockerfile (golang:1.22-alpine) 构建'
type: project
---

本机（Windows）未安装 Go，也无 Docker/容器运行时，无法本地执行 `go build`。

**Why:** 项目是 Go 单文件应用，通过 Dockerfile（golang:1.22-alpine 多阶段构建）打包，用户在 Docker/CI 环境中完成编译验证。

**How to apply:** 涉及 Go 代码修改后，不要尝试本地 `go build`；改为做细致的人工语法/逻辑复查，并提示用户在 Docker/CI 中验证编译。