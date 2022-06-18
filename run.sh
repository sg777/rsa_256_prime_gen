#!/bin/sh
g++ -o rsa_256_prime_gen rsa_256_prime_gen.c -g -w -fpermissive -pthread -ldl -I/usr/local/openssl/include -L/usr/local/openssl/lib -lcrypto -lsqlite3

