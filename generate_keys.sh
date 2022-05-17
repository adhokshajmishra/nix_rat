#!/bin/bash

./mbedtls-2.9.0/build/programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=ssl_keypair.key

./mbedtls-2.9.0/build/programs/x509/cert_write selfsign=1 issuer_key=ssl_keypair.key \
                         issuer_name=CN=myserver,O=myorganisation,C=NL \
                         not_before=20130101000000 not_after=20251231235959 \
                         is_ca=1 max_pathlen=0 output_file=ssl_certificate.pem

xxd -i ssl_keypair.key > ./src/keys/local_ssl_keypair.h
xxd -i ssl_certificate.pem > ./src/keys/local_ssl_certificate.h
