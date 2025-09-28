#!/bin/bash

set -euo pipefail

CRL_URL="https://host.docker.internal:8100/crl"
DEST_CRL_PATH="/etc/nginx/crl/ca-chain.crl"
TMP_CRL_PATH="/tmp/ca-chain.crl.tmp"

mkdir -p /etc/nginx/crl

while true; do
  if curl -v -sf --cacert /usr/local/interCA.pem "$CRL_URL" -o "$TMP_CRL_PATH"; then
    if openssl crl -in "$TMP_CRL_PATH" -noout > /dev/null 2>&1; then
      mv "$TMP_CRL_PATH" "$DEST_CRL_PATH"
      echo "[INFO]  CRL mise à jour depuis $CRL_URL"
      nginx -s reload
    else
      echo "[ERROR] Fichier CRL invalide reçu. Pas de remplacement."
      rm -f "$TMP_CRL_PATH"
    fi
  else
    echo "[ERROR] Échec de téléchargement depuis $CRL_URL"
  fi
  sleep 300
done

