#!/bin/bash

mkdir -p demoCA/newcerts
touch demoCA/index.txt demoCA/index.txt.attr
echo '01' > demoCA/serial

# Generate Root Private Key
certtool --generate-privkey --outfile x509-root-key.pem --rsa

# Generate Root Certificate
certtool --generate-self-signed --template root-template.txt --load-privkey x509-root-key.pem --outfile x509-root-cert.pem

# Generate Intermediate Certificate Key
certtool --generate-privkey --outfile x509-interm-key.pem --rsa

# Generate Intermediate Certificate Signing Request
certtool --generate-request --template interm-template.txt --load-privkey x509-interm-key.pem --outfile x509-interm-cert.csr

# Sign Intermediat Certificate Signing Request
openssl ca -batch -days 365000 -keyfile x509-root-key.pem -cert x509-root-cert.pem -policy policy_anything -config interm.cnf -extensions v3_intermediate -notext -out x509-interm-cert.pem -infiles x509-interm-cert.csr

# Generate Server Key
certtool --generate-privkey --outfile x509-server-key.pem --rsa

# Generate Server Signing Request
certtool --generate-request --template server-template.txt --load-privkey x509-server-key.pem --outfile x509-server-cert.csr

# Sign Server Certificate Request
openssl ca -batch -days 36500 -keyfile x509-interm-key.pem -cert x509-interm-cert.pem -policy policy_anything -notext -out x509-server-cert.pem -infiles x509-server-cert.csr

# Start root CA's OCSP Responder
openssl ocsp -index demoCA/index.txt -port 8080 -rsigner x509-root-cert.pem -rkey x509-root-key.pem -CA x509-root-cert.pem -text & ocsp_server=$!

# Save OCSP OK Response
openssl ocsp -sha256 -CAfile x509-root-cert.pem -issuer x509-root-cert.pem -cert x509-interm-cert.pem -url http://127.0.0.1:8080 -noverify -resp_text -respout ocsp_resp_ok.der

sleep 1;

# Kill OCSP Server
kill -9 $ocsp_server

# Revoke Intermediate Certificate
openssl ca -keyfile x509-root-key.pem -cert x509-root-cert.pem -revoke x509-interm-cert.pem 

# Start root CA's OCSP Responder
openssl ocsp -index demoCA/index.txt -port 8080 -rsigner x509-root-cert.pem -rkey x509-root-key.pem -CA x509-root-cert.pem -text & ocsp_server=$!

# Save OCSP OK Response
openssl ocsp -sha256 -CAfile x509-root-cert.pem -issuer x509-root-cert.pem -cert x509-interm-cert.pem -url http://127.0.0.1:8080 -noverify -resp_text -respout ocsp_resp_revoked.der

sleep 1;

# Kill OCSP Server
kill -9 $ocsp_server

# == BIBLIOGRAPHY ==
# 1. https://medium.com/@bhashineen/create-your-own-ocsp-server-ffb212df8e63
# 2. https://gitlab.com/gnuwget/wget/blob/master/tests/certs/create-certs.sh
# 3. https://gitlab.com/gnuwget/wget2/blob/master/tests/certs/README