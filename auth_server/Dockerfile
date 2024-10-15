FROM golang:1.17-alpine AS build
 
RUN apk update && apk add make

WORKDIR /go/src/github.com/cesanta/docker_auth/auth_server

COPY . .

RUN make build

FROM alpine

EXPOSE 5001
COPY --from=build /go/src/github.com/cesanta/docker_auth/auth_server/auth_server /
ENTRYPOINT ["/auth_server"]
