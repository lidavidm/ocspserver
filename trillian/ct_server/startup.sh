#!/usr/bin/env bash

docker run -d --name ct_server -p 80:80 -v "$(readlink -m ./config):/config" ct_server
