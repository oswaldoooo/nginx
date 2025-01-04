#!/bin/bash
# 打包脚本
set -e
./auto/configure --with-http_v2_module --with-http_ssl_module
make
make install
tar -zcf nginx.tar.gz /usr/local/nginx
rm -rf /usr/local/nginx