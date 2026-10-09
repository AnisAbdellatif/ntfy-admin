NTFY_COMPOSE := integration/docker-compose.yml
GO ?= go

.PHONY: build test vet integration integration-up integration-down docker clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o ntfy-admin ./cmd/ntfy-admin

vet:
	$(GO) vet ./...
	$(GO) vet -tags integration ./...

test:
	$(GO) test ./...

integration-up:
	docker compose -f $(NTFY_COMPOSE) up -d --wait

integration-down:
	docker compose -f $(NTFY_COMPOSE) down -v

# Runs the integration test against the pinned ntfy from integration/docker-compose.yml.
integration: integration-up
	NTFY_URL=http://localhost:18080 $(GO) test -count=1 -tags integration -run Integration -v ./internal/web/; \
	status=$$?; $(MAKE) integration-down; exit $$status

docker:
	docker build -t ntfy-admin:latest .

clean:
	rm -f ntfy-admin
