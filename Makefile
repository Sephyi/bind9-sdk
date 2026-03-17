# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

.PHONY: test-integration test-integration-up test-integration-down

COMPOSE := podman-compose -f tests/bind9/podman-compose.yml

test-integration-up:
	$(COMPOSE) up -d
	@echo "Waiting for BIND9 health..."
	@for i in $$(seq 1 30); do \
		if $(COMPOSE) exec bind9 rndc status >/dev/null 2>&1; then \
			echo "BIND9 healthy after $$i seconds"; \
			break; \
		fi; \
		sleep 1; \
	done

test-integration-down:
	$(COMPOSE) down -v

test-integration: test-integration-up
	cargo test --workspace -- --ignored; \
	status=$$?; \
	$(MAKE) test-integration-down; \
	exit $$status
