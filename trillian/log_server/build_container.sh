#!/bin/sh

set -e

DOCKERFILE_DIR=$(pwd)

# go get -d -u github.com/google/trillian
# cd $GOPATH/src/github.com/google/trillian

# cd server/trillian_log_server
# CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o $DOCKERFILE_DIR/main .

cd $DOCKERFILE_DIR
sudo docker build -t trillian_log .
