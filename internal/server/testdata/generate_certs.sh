#!/bin/bash

# Generate CA private key and certificate
openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout ca-key.pem -out ca.pem -subj "/C=US/ST=Test/L=Test/O=Test/CN=Test CA"

# Generate server private key
openssl genrsa -out key.pem 2048

# Generate server CSR
openssl req -new -key key.pem -out server.csr -subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost"

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out cert.pem -days 365

# Clean up CSR and serial files
rm server.csr ca.srl 