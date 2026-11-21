.PHONY: up-insecure up-hardened pki test down

pki:
	bash scripts/setup_pki.sh

up-insecure:
	docker compose -f modes/insecure/docker-compose.yml up -d

up-hardened: pki
	docker compose -f modes/hardened/docker-compose.yml up -d

test: pki
	docker compose -f modes/insecure/docker-compose.yml config -q
	docker compose -f modes/hardened/docker-compose.yml config -q
	python3 -m pytest -v tests/test_zero_trust.py
	bash scripts/capture_proof.sh
	bash scripts/rotate_certs.sh

down:
	docker compose -f modes/insecure/docker-compose.yml down 2>/dev/null || true
	docker compose -f modes/hardened/docker-compose.yml down 2>/dev/null || true
