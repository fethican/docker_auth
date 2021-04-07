.PHONY: update-deps build docker-build

all: build

build:
	CGO_ENABLED=0 go build

docker-build: build
	docker build -t $(IMAGE):latest .

docker-push-latest:
	docker push cesanta/docker_auth:latest

docker-push-stable:
	docker tag -f cesanta/docker_auth:latest cesanta/docker_auth:stable
	docker push cesanta/docker_auth:stable
