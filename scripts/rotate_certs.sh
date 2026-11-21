#!/usr/bin/env bash
# Demonstrates zero-downtime short-lived certificate rotation for billing-api, auth-service, and gateway
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "=== Before Rotation: Current billing-api Certificate Serial ==="
openssl x509 -in "${ROOT_DIR}/certs/billing-api.crt" -noout -serial -dates
bash "${ROOT_DIR}/scripts/setup_pki.sh" --rotate
echo "=== After Rotation: New billing-api Certificate Serial ==="
openssl x509 -in "${ROOT_DIR}/certs/billing-api.crt" -noout -serial -dates
