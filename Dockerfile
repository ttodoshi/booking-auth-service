FROM golang:1.21-alpine AS builder

RUN apk add --no-cache make

WORKDIR /usr/local/src/app

COPY go.mod go.sum ./
COPY internal internal
COPY pkg pkg
COPY cmd cmd
COPY docs docs
COPY Makefile ./

RUN make build

FROM alpine:latest AS final

WORKDIR /usr/local/src/app/bin

COPY --from=builder /usr/local/src/app/bin/app .

EXPOSE 8090

CMD ["./app"]
