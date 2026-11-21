# zero-trust-mtls-lab: Service-to-Service Mutual TLS (mTLS 1.3) & Internal PKI Lab

## Why I built this
In many microservice architectures, TLS is terminated at the edge load balancer and internal services talk to each other over plain HTTP inside a shared VPC or Docker network, trusting headers like `X-Caller-Identity`. The problem is that if an attacker compromises any container on that internal network, they can sniff plaintext traffic and spoof internal headers to hit sensitive backend APIs directly.

I built this lab around three microservices (`gateway`, `auth-service`, and `billing-api`) to compare two deployable modes:
1. **`modes/insecure/` (Plaintext HTTP)**: Services communicate over unencrypted HTTP with no client certificate checks. Anyone on the network can query `billing-api` directly with `X-Caller-Identity: spoofed-internal-admin` and dump customer invoices.
2. **`modes/hardened/` (Strict Zero-Trust mTLS 1.3)**: Every service enforces **Mutual TLS 1.3 (`ssl.CERT_REQUIRED`)** backed by an internal 2-tier PKI (**Root CA -> Intermediate CA -> 7-day leaf certificates**) and checks the peer certificate's X.509 Common Name (`CN`) before returning data.

## Architecture diagram

```text
+-----------------------------------------------------------------------------------+
| Internal 2-Tier PKI (scripts/setup_pki.sh & scripts/rotate_certs.sh)              |
|   Root CA (4096-bit) ---> Intermediate CA (pathlen:0) ---> 7-Day Service Certs    |
+-----------------------------------------+-----------------------------------------+
                                          |
       +----------------------------------+----------------------------------+
       |                                                                     |
       v Mode 1: modes/insecure/ (Plaintext HTTP)                            v Mode 2: modes/hardened/ (Strict mTLS 1.3)
+-----------------------------------------+   +-----------------------------------------+
| gateway (:9101)                         |   | gateway (:9201, CN=gateway)             |
|   |-- HTTP GET /verify (No Auth)        |   |   |-- mTLS 1.3 + Client Cert CN=gateway |
|   v                                     |   |   v                                     |
| auth-service (:9102)                    |   | auth-service (:9202, verifies CN)       |
|   |-- HTTP GET /v1/invoices             |   |   |-- mTLS 1.3 + Client Cert CN=gateway |
|   |   (Vulnerable to Header Spoofing!)  |   |   |   (Rejects missing/rogue certs!)    |
|   v                                     |   |   v                                     |
| billing-api (:9103) -> Cleartext JSON   |   | billing-api (:9203) -> TLS_AES_256_GCM  |
+-----------------------------------------+   +-----------------------------------------+
```

## How I designed the PKI and identity checks
1. **Two-tier CA hierarchy ([scripts/setup_pki.sh](scripts/setup_pki.sh))**:
   Rather than signing workload certificates directly with the Root CA, `setup_pki.sh` generates a 4096-bit offline Root CA (`root-ca.crt`) and signs a 4096-bit Intermediate Microservice CA (`intermediate-ca.crt`) with `basicConstraints = critical, CA:TRUE, pathlen:0`. Setting `pathlen:0` ensures that even if the Intermediate CA were compromised, it cannot issue another subordinate CA.
2. **Short-lived leaf certificates & rotation ([scripts/rotate_certs.sh](scripts/rotate_certs.sh))**:
   Each service (`gateway`, `auth-service`, `billing-api`) receives a 7-day certificate with `extendedKeyUsage = serverAuth, clientAuth` and Subject Alternative Names (`DNS:<service>, DNS:localhost, IP:127.0.0.1`). Running `scripts/rotate_certs.sh` issues fresh serial numbers under the Intermediate CA without touching the Root CA.
3. **Authentication + CN Authorization ([services/microservices.py](services/microservices.py))**:
   Verifying that a certificate chains up to `ca-chain.crt` only proves the caller is *some* container in the cluster. Inside `BillingHandler` and `AuthHandler`, I also inspect `self.connection.getpeercert()` to verify that the caller's X.509 `commonName` is explicitly authorized (`cn in ("gateway", "auth-service")`), binding identity to the certificate instead of an HTTP header.

## Verification results (`make test`)
My integration test suite ([tests/test_zero_trust.py](tests/test_zero_trust.py)) and wire-capture proof ([scripts/capture_proof.sh](scripts/capture_proof.sh)) verify four scenarios:

| Test Case | `modes/insecure/` (Plaintext HTTP) | `modes/hardened/` (Strict mTLS 1.3) | What happens under the hood |
|---|---|---|---|
| Direct request to `billing-api` without a client cert | `200 OK` (Leaks invoice `INV-9001`, `$48,500`) | **Rejected (`SSLError: CERTIFICATE_REQUIRED`)** | TLS 1.3 handshake aborts before any HTTP bytes are processed |
| Direct request with `X-Caller-Identity: spoofed-internal-admin` | `200 OK` (`authenticated_caller: spoofed-internal-admin`) | **Blocked** | Hardened mode ignores `X-Caller-Identity` and reads identity from `peercert` `CN` |
| Request presenting an untrusted self-signed `rogue.crt` (`CN=billing-api`) | N/A | **Rejected (`SSLError: UNKNOWN_CA`)** | Rejected because `rogue.crt` is not signed by `intermediate-ca.crt` |
| Valid `gateway` -> `auth-service` + `billing-api` mTLS call | `200 OK` (Cleartext JSON on wire) | **`200 OK` (`mTLS-Verified:gateway`)** | Negotiates `TLSv1.3` / `TLS_AES_256_GCM_SHA384` (256-bit AEAD ciphertext) |

### Automated PKI setup, pytest, wire proof, and rotation output
![mtls](docs/screenshots/01_zero_trust_mtls.png)

## How to run it
```bash
# Run PKI generation, Docker Compose validation, pytest suite, wire proof, and cert rotation
make test

# Or launch either mode via Docker Compose
make up-insecure
make up-hardened
make down
```
