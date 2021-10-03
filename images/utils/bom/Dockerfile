FROM golang:1.16.6 as builder
WORKDIR /app

RUN apt-get install git
ADD go.mod go.sum /app/
ADD pkg /app/pkg
ADD cmd /app/cmd
ADD internal /app/internal
ADD .git /app/.git

RUN pwd && ls -l && go get -d -v ./...

RUN CGO_ENABLED=0 go build -v -trimpath -ldflags "-s -w \
    -X bom.buildDate=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
    -X bom.gitCommit=$(git rev-parse HEAD 2>/dev/null || echo unknown) \
    -X bom.gitVersion=$(git describe --tags --abbrev=0 || echo unknown)" \
    -o bom ./cmd/bom/ || return 1

RUN ./bom --help

# FROM alpine:3.9.6
FROM debian:bullseye-slim

#RUN apk update && apk add git go
RUN apt-get -q update && apt-get -qqy install git golang

COPY --from=builder /app/bom /bom

ENTRYPOINT ["/bom"]

