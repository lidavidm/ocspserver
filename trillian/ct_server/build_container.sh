#!/bin/sh

set -e

DOCKERFILE_DIR=$(pwd)

go get -d -u github.com/google/trillian

cd $GOPATH/src/github.com/google/trillian
go get -d -v -t ./...
CGO_ENABLED=0 GOOS=linux go build ./...

cd examples/ct/ct_server
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o $DOCKERFILE_DIR/main .

cd $DOCKERFILE_DIR
sudo docker build -t ct_server .
