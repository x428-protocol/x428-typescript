.PHONY: setup test build typecheck update-vectors clean

## First-time setup: install deps and init submodule
setup:
	git submodule update --init
	npm install

## Run tests
test: setup
	npx vitest run

## Type check
typecheck:
	npx tsc --noEmit

## Build
build:
	npx tsc

## Pull latest conformance vectors from spec repo
update-vectors:
	git -C vendor/spec pull origin main
	@echo "Submodule updated. Run 'make test' to verify, then commit vendor/spec."

## Clean build artifacts
clean:
	rm -rf dist
