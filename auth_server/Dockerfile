FROM golang:1.16-alpine

COPY . .

RUN curl -q https://github.com/Masterminds/glide/releases/download/v0.13.3/glide-v0.13.3-freebsd-amd64.tar.gz | tar -xz --strip-components 1 \
	&& ./glide install

FROM scratch

EXPOSE 5001
ADD auth_server /
ENTRYPOINT ["/auth_server"]
