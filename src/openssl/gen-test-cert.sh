#!/bin/sh

if [ $# -lt 1 ]; then
  echo "USAGE: `basename $0` path/to/cert/file"
  exit
fi
CSR=request.csr
openssl req -config openssl.cnf -new -key test-key.pem -out $CSR
openssl ca -config openssl.cnf -days 10000 -in request.csr -out $1
rm -f $CSR

