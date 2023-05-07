#!/bin/sh

set -e

# Generates a self-signed Ed25519 PEM cert and key
# in the current working dir.

openssl req -x509 -newkey ed25519 -days 365 -nodes \
  -keyout key.pem -out cert.pem -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
