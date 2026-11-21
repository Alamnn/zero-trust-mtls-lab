#!/usr/bin/env python3
"""Zero-Trust Microservices Runtime (gateway, auth-service, billing-api) supporting Insecure HTTP and Strict mTLS."""
import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request


def make_mtls_context(cert_dir: str, svc_name: str, is_server: bool) -> ssl.SSLContext:
    mode = ssl.Purpose.CLIENT_AUTH if is_server else ssl.Purpose.SERVER_AUTH
    ctx = ssl.create_default_context(mode)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=os.path.join(cert_dir, "ca-chain.crt"))
    ctx.load_cert_chain(
        certfile=os.path.join(cert_dir, f"{svc_name}-fullchain.crt"),
        keyfile=os.path.join(cert_dir, f"{svc_name}.key"),
    )
    if is_server:
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class BillingHandler(BaseHTTPRequestHandler):
    mode = "insecure"

    def do_GET(self):
        caller_role = self.headers.get("X-Caller-Identity", "anonymous")
        if self.mode == "hardened":
            peercert = self.connection.getpeercert()
            if not peercert:
                self._json(403, {"error": "mTLS client certificate required"})
                return
            cn = dict(x[0] for x in peercert.get("subject", ())).get("commonName", "")
            if cn not in ("gateway", "auth-service"):
                self._json(403, {"error": f"Untrusted client certificate CN={cn}"})
                return
            caller_role = f"mTLS-Verified:{cn}"

        if self.path == "/v1/invoices":
            self._json(200, {
                "service": "billing-api",
                "mode": self.mode,
                "authenticated_caller": caller_role,
                "invoices": [{"id": "INV-9001", "amount_usd": 48500, "card_last4": "4242"}],
            })
        else:
            self._json(404, {"error": "not found"})

    def _json(self, code: int, payload: dict):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class AuthHandler(BaseHTTPRequestHandler):
    mode = "insecure"

    def do_GET(self):
        if self.mode == "hardened":
            peercert = self.connection.getpeercert()
            cn = dict(x[0] for x in peercert.get("subject", ())).get("commonName", "") if peercert else ""
            if cn != "gateway":
                self._json(403, {"error": f"Only gateway CN allowed, got {cn}"})
                return
        self._json(200, {"service": "auth-service", "mode": self.mode, "token_valid": True, "scope": "billing:read"})

    def _json(self, code: int, payload: dict):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class GatewayHandler(BaseHTTPRequestHandler):
    mode = "insecure"
    cert_dir = "certs"
    auth_url = "http://127.0.0.1:9102/verify"
    billing_url = "http://127.0.0.1:9103/v1/invoices"

    def do_GET(self):
        if self.path != "/checkout":
            self._json(404, {"error": "not found"})
            return
        try:
            if self.mode == "hardened":
                c_ctx = make_mtls_context(self.cert_dir, "gateway", is_server=False)
                with urllib.request.urlopen(self.auth_url, context=c_ctx, timeout=4) as r1:
                    auth_data = json.loads(r1.read().decode())
                with urllib.request.urlopen(self.billing_url, context=c_ctx, timeout=4) as r2:
                    bill_data = json.loads(r2.read().decode())
            else:
                req = urllib.request.Request(self.billing_url, headers={"X-Caller-Identity": "gateway-http"})
                with urllib.request.urlopen(self.auth_url, timeout=4) as r1:
                    auth_data = json.loads(r1.read().decode())
                with urllib.request.urlopen(req, timeout=4) as r2:
                    bill_data = json.loads(r2.read().decode())
            self._json(200, {"gateway": "ok", "mode": self.mode, "auth": auth_data, "billing": bill_data})
        except Exception as e:
            self._json(502, {"error": str(e)})

    def _json(self, code: int, payload: dict):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass
