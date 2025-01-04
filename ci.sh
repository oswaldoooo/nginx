#!/bin/bash
set -e
docker run -v ./:/root/nginx --rm nginx-build:arm64 -w /root/nginx build.sh
mkdir -p /opt/packages/nginx/$(uname)-$(uname -m)
mv nginx.tar.gz /opt/packages/nginx/$(uname)-$(uname -m)/nginx-$(date "+%Y%m%d%H%M").tar.gz
