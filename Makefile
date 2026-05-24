SHELL := /bin/bash

MODULE  := github.com/rykth/neth
BIN_DIR := bin
NETHD       := $(BIN_DIR)/nethd
NETH_CERT   := $(BIN_DIR)/neth-cert

# All Go source files (excluding generated and vendor)
GO_SOURCES := $(shell find . -name '*.go' \
	-not -path './vendor/*' \
	-not -name '*.pb.go')

VM_LAB := vm-lab

.PHONY: all build nethd neth-cert proto test test-race lint clean help \
        vm-start vm-stop vm-clean

all: build

## build: compile both binaries into bin/
build: nethd neth-cert

nethd: $(BIN_DIR) $(GO_SOURCES)
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o $(NETHD) ./cmd/nethd

neth-cert: $(BIN_DIR) $(GO_SOURCES)
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o $(NETH_CERT) ./cmd/neth-cert

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

## proto: regenerate protobuf bindings into nethpb/ (requires protoc + protoc-gen-go)
proto:
	mkdir -p nethpb
	PATH="$$PATH:$$HOME/.local/bin/protoc/bin" protoc \
		--go_out=. \
		--go_opt=module=$(MODULE) \
		neth.proto

## test: run all tests (short, no race detector)
test:
	go test -count=1 ./...

## test-race: run all tests with the race detector
test-race:
	go test -race -count=1 ./...

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## clean: remove compiled binaries
clean:
	rm -rf $(BIN_DIR)

## vm-start: build binaries and boot 3 QEMU VMs (lighthouse + node-a + node-b)
vm-start: build
	sudo $(VM_LAB)/start.sh

## vm-stop: gracefully shut down the VMs and remove bridge/TAP devices
vm-stop:
	sudo $(VM_LAB)/stop.sh

## vm-clean: shut down VMs and delete overlay disks / cloud-init ISOs
vm-clean:
	sudo $(VM_LAB)/stop.sh --clean

## help: list available targets
help:
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## //'
