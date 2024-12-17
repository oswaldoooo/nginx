#!/bin/bash
# encrypt tools
function encrypt(){
  gcc -o encryptLine -std=gnu99 -I../src/core/ ../src/core/encrypt.c encryptLine.c $(pkg-config --cflags --libs openssl)
  gcc -o decryptLine -std=gnu99 -I../src/core/ ../src/core/encrypt.c decryptLine.c $(pkg-config --cflags --libs openssl)
}
$1