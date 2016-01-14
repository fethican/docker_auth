.PHONY: update-deps build docker-build

all: build

update-deps:
	go get -v github.com/jteeuwen/go-bindata/... .

build:
	GO15VENDOREXPERIMENT=1 go generate ./...
	GO15VENDOREXPERIMENT=1 go build

release:
	CGO_ENABLED=0 go build -a -tags netgo -installsuffix netgo

docker-build: update-deps build
	docker build -t cesanta/docker_auth -f Dockerfile .

docker-push-latest:
	docker push cesanta/docker_auth:latest

docker-push-stable:
	docker tag -f cesanta/docker_auth:latest cesanta/docker_auth:stable
	docker push cesanta/docker_auth:stable
