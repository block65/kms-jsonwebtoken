
SRCS = $(wildcard lib/**)

all: dist

.PHONY: deps
deps: node_modules

.PHONY: clean
clean:
	pnpm tsc -b --clean
	rm -rf dist
	rm -rf __tests__/dist

.PHONY: test
test: node_modules
	pnpm tsc -b
	NODE_OPTIONS=--experimental-vm-modules pnpm jest

node_modules: package.json
	pnpm install

dist: node_modules tsconfig.json $(SRCS)
	pnpm tsc

.PHONY: dev
dev:
	pnpm tsc -b -w

.PHONY: pretty
pretty: node_modules
	pnpm eslint --fix . || true
	pnpm prettier --write .
