#!/usr/bin/env python3
"""Integration tests verifying Insecure HTTP header spoofing vs Hardened Zero-Trust mTLS enforcement."""
import json
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

import pytest
from services.microservices import AuthHandler, BillingHandler, GatewayHandler, make_mtls_context

ROOT = Path(__file__).parent.parent
CERT_DIR = ROOT / "certs"


@pytest.fixture(scope="module", autouse=True)
def ensure_pki():
    if not (CERT_DIR / "ca-chain.crt").exists():
        subprocess.run(["bash", str(ROOT / "scripts/setup_pki.sh")], check=True)


def _start_server(server: HTTPServer):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def test_insecure_mode_allows_unauthenticated_and_spoofed_headers():
    class InsecureBilling(BillingHandler):
        mode = "insecure"

    class InsecureAuth(AuthHandler):
        mode = "insecure"

    class InsecureGateway(GatewayHandler):
        mode = "insecure"
        auth_url = "http://127.0.0.1:19102/verify"
        billing_url = "http://127.0.0.1:19103/v1/invoices"

    s_auth = _start_server(HTTPServer(("127.0.0.1", 19102), InsecureAuth))
    s_bill = _start_server(HTTPServer(("127.0.0.1", 19103), InsecureBilling))
    s_gw = _start_server(HTTPServer(("127.0.0.1", 19101), InsecureGateway))
    time.sleep(0.1)
    try:
        # Direct unauthorized request to billing-api with spoofed X-Caller-Identity header succeeds (200 OK)
        req = urllib.request.Request(
            "http://127.0.0.1:19103/v1/invoices",
            headers={"X-Caller-Identity": "spoofed-internal-admin"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["authenticated_caller"] == "spoofed-internal-admin"
            assert data["invoices"][0]["id"] == "INV-9001"
    finally:
        s_auth.shutdown()
        s_bill.shutdown()
        s_gw.shutdown()


def test_hardened_mtls_mode_rejects_unauthenticated_and_rogue_certs_and_allows_valid_mtls():
    class HardenedBilling(BillingHandler):
        mode = "hardened"

    class HardenedAuth(AuthHandler):
        mode = "hardened"

    class HardenedGateway(GatewayHandler):
        mode = "hardened"
        cert_dir = str(CERT_DIR)
        auth_url = "https://localhost:19202/verify"
        billing_url = "https://localhost:19203/v1/invoices"

    s_auth = HTTPServer(("127.0.0.1", 19202), HardenedAuth)
    s_auth.socket = make_mtls_context(str(CERT_DIR), "auth-service", is_server=True).wrap_socket(s_auth.socket, server_side=True)
    _start_server(s_auth)

    s_bill = HTTPServer(("127.0.0.1", 19203), HardenedBilling)
    s_bill.socket = make_mtls_context(str(CERT_DIR), "billing-api", is_server=True).wrap_socket(s_bill.socket, server_side=True)
    _start_server(s_bill)

    s_gw = HTTPServer(("127.0.0.1", 19201), HardenedGateway)
    s_gw.socket = make_mtls_context(str(CERT_DIR), "gateway", is_server=True).wrap_socket(s_gw.socket, server_side=True)
    _start_server(s_gw)
    time.sleep(0.1)

    try:
        # 1. Request without client certificate MUST fail TLS handshake
        no_cert_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        no_cert_ctx.load_verify_locations(cafile=str(CERT_DIR / "ca-chain.crt"))
        with pytest.raises((ssl.SSLError, urllib.error.URLError)):
            urllib.request.urlopen("https://localhost:19203/v1/invoices", context=no_cert_ctx, timeout=3)

        # 2. Request with rogue self-signed client certificate MUST fail TLS handshake
        rogue_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        rogue_ctx.load_verify_locations(cafile=str(CERT_DIR / "ca-chain.crt"))
        rogue_ctx.load_cert_chain(certfile=str(CERT_DIR / "rogue.crt"), keyfile=str(CERT_DIR / "rogue.key"))
        with pytest.raises((ssl.SSLError, urllib.error.URLError)):
            urllib.request.urlopen("https://localhost:19203/v1/invoices", context=rogue_ctx, timeout=3)

        # 3. Valid mTLS service-to-service chain (gateway -> auth-service + billing-api) MUST succeed (200 OK)
        valid_ctx = make_mtls_context(str(CERT_DIR), "gateway", is_server=False)
        with urllib.request.urlopen("https://localhost:19201/checkout", context=valid_ctx, timeout=3) as resp:
            assert resp.status == 200
            payload = json.loads(resp.read().decode())
            assert payload["gateway"] == "ok"
            assert payload["auth"]["token_valid"] is True
            assert payload["billing"]["authenticated_caller"] == "mTLS-Verified:gateway"
    finally:
        s_auth.shutdown()
        s_bill.shutdown()
        s_gw.shutdown()
