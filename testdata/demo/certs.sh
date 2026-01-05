#!/bin/bash

# Create output directory
mkdir -p testdata/demo
cd testdata/demo

echo "Generating demo certificates..."

# ==========================================
# 1. Generate Root CA
#    (Explicitly setting CA:TRUE to ensure it can sign the Intermediate CA)
# ==========================================
# Generate key
openssl genrsa -out root.key 2048

# Generate CSR
openssl req -new -key root.key -out root.csr \
  -subj "/C=JP/O=Y509 Org/CN=Y509 Demo Root CA"

# Extension settings (Ensure CA:TRUE is set)
cat > root.ext << EOF
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

# Self-sign
openssl x509 -req -in root.csr -signkey root.key \
  -out root.crt -days 3650 -sha256 -extfile root.ext

# ==========================================
# 2. Generate Intermediate CA
# ==========================================
openssl req -new -nodes \
  -keyout int.key -out int.csr \
  -subj "/C=JP/O=Y509 Org/OU=Infrastructure/CN=Y509 Demo Intermediate CA"

# Extension settings for Intermediate CA
cat > int.ext << EOF
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

# Sign with Root CA
openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out int.crt -days 1825 -sha256 -extfile int.ext

# ==========================================
# 3. Generate Leaf Certificate
#    (Includes multiple SANs for demonstration)
# ==========================================
openssl req -new -nodes \
  -keyout leaf.key -out leaf.csr \
  -subj "/C=JP/ST=Tokyo/O=Example Corp/CN=example.com"

# SAN settings
cat > leaf.ext << EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = example.com
DNS.2 = www.example.com
DNS.3 = api.example.com
DNS.4 = dashboard.internal
IP.1 = 127.0.0.1
EOF

# Sign with Intermediate CA
openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial \
  -out leaf.crt -days 365 -sha256 -extfile leaf.ext

# ==========================================
# 4. Generate Expiring Certificate
#    (Short validity to test warning colors in TUI)
# ==========================================
openssl req -new -nodes \
  -keyout expired.key -out expired.csr \
  -subj "/C=US/O=Old Legacy/CN=expiring.example.org"

# Set validity to 1 day
openssl x509 -req -in expired.csr -CA int.crt -CAkey int.key -CAcreateserial \
  -out expired.crt -days 1 -sha256

# ==========================================
# Concatenate certificates into a single PEM file
# Order: Leaf -> Expiring -> Intermediate -> Root
# ==========================================
cat leaf.crt expired.crt int.crt root.crt > certs.pem

# Cleanup temporary files
# rm *.key *.csr *.crt *.ext *.srl

echo "Done! Created testdata/demo/certs.pem"
