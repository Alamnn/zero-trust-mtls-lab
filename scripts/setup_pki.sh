#!/usr/bin/env bash
# Generates an internal 2-tier PKI (Root CA -> Intermediate CA -> Short-Lived Server/Client Certs)
# for gateway, auth-service, and billing-api, plus supports automated certificate rotation (--rotate).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"
mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

ROTATE="${1:-}"

if [[ "${ROTATE}" != "--rotate" || ! -f ca-chain.crt ]]; then
  echo "[*] Generating Zero-Trust Internal Root CA and Intermediate CA..."
  openssl genrsa -out root-ca.key 4096 2>/dev/null
  openssl req -x509 -new -nodes -key root-ca.key -sha256 -days 3650 \
    -subj "/C=US/O=ZeroTrustLab/CN=ZeroTrust Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out root-ca.crt 2>/dev/null

  openssl genrsa -out intermediate-ca.key 4096 2>/dev/null
  openssl req -new -key intermediate-ca.key \
    -subj "/C=US/O=ZeroTrustLab/CN=ZeroTrust Intermediate Microservice CA" \
    -out intermediate-ca.csr 2>/dev/null

  cat <<'EXT' > ca_inter.ext
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EXT
  openssl x509 -req -in intermediate-ca.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial \
    -out intermediate-ca.crt -days 1825 -sha256 -extfile ca_inter.ext 2>/dev/null
  cat intermediate-ca.crt root-ca.crt > ca-chain.crt
fi

issue_service_cert() {
  local svc="$1"
  echo "[*] Issuing short-lived (7-day) mTLS certificate for service: ${svc}..."
  openssl genrsa -out "${svc}.key" 2048 2>/dev/null
  openssl req -new -key "${svc}.key" \
    -subj "/C=US/O=ZeroTrustLab/OU=Microservices/CN=${svc}" \
    -out "${svc}.csr" 2>/dev/null

  cat <<EXT > "${svc}.ext"
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:${svc}, DNS:localhost, IP:127.0.0.1
EXT
  openssl x509 -req -in "${svc}.csr" -CA intermediate-ca.crt -CAkey intermediate-ca.key -CAcreateserial \
    -out "${svc}.crt" -days 7 -sha256 -extfile "${svc}.ext" 2>/dev/null
  cat "${svc}.crt" intermediate-ca.crt > "${svc}-fullchain.crt"
  openssl x509 -in "${svc}.crt" -noout -serial -subject -dates
}

for s in gateway auth-service billing-api; do
  issue_service_cert "${s}"
done

# Generate an untrusted rogue self-signed client certificate to test mTLS rejection
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.crt -days 1 \
  -subj "/C=US/O=Attacker/CN=billing-api" 2>/dev/null

echo "[+] PKI setup complete in ${CERT_DIR}"
