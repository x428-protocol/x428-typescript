.PHONY: setup test build typecheck update-vectors check-vectors clean demo demo-apps demo-workers deploy-workers

## First-time setup: install deps and init submodule
setup:
	git submodule update --init
	npm install

## Check if spec submodule is behind origin
check-vectors:
	@git -C vendor/spec fetch origin --tags --quiet 2>/dev/null || true
	@LOCAL=$$(git -C vendor/spec rev-parse HEAD); \
	REMOTE=$$(git -C vendor/spec rev-parse origin/main 2>/dev/null); \
	if [ "$$LOCAL" != "$$REMOTE" ] && [ -n "$$REMOTE" ]; then \
		echo ""; \
		echo "⚠  Spec vectors may be out of date."; \
		echo "   Local:  $$LOCAL"; \
		echo "   Remote: $$REMOTE"; \
		echo "   Run 'make update-vectors' to pull latest."; \
		echo ""; \
	fi

## Run tests (warns if vectors are stale)
test: setup check-vectors
	npm test

## Type check
typecheck:
	npm run typecheck

## Build
build:
	npm run build

## Pull latest conformance vectors from spec repo
update-vectors:
	git -C vendor/spec fetch origin --tags
	git -C vendor/spec checkout origin/main
	@echo ""
	@echo "Submodule updated. Run 'make test' to verify, then:"
	@echo "  git add vendor/spec && git commit -m 'update spec vectors'"

## Run elicitation demo (stdio, use with MCP Inspector)
demo:
	npx tsx examples/demo-server.ts

## Run MCP Apps demo (HTTP on :3428, use with Inspector or Claude Desktop)
demo-apps:
	npx tsx examples/demo-server-apps.ts

## Run Workers demo locally (requires wrangler)
demo-workers:
	npm run dev --prefix examples/demo-server-workers

## Deploy Workers demo (requires CLOUDFLARE_ACCOUNT_ID)
deploy-workers:
	npm run deploy --prefix examples/demo-server-workers

## Clean build artifacts
clean:
	rm -rf packages/core/dist packages/mcp/dist
