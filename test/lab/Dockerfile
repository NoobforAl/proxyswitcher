# Builds proxyswitcher and the lab's fake target and upstream proxy.
FROM golang:1.27 AS build
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -o /out/proxyswitcher ./cmd/proxyswitcher
WORKDIR /src/test/lab
RUN go build -o /out/target ./target && go build -o /out/upstream ./upstream

FROM alpine:3.20
COPY --from=build /out/ /usr/local/bin/
