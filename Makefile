BINARY_NAME=wat
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -ldflags "-X github.com/ilijad1/well-architected-terraform/cmd.version=$(VERSION) -X github.com/ilijad1/well-architected-terraform/cmd.commit=$(COMMIT)"

.PHONY: build test lint clean install

build:
	go build $(LDFLAGS) -o $(BINARY_NAME) .

test:
	go test ./... -v

test-short:
	go test ./...

lint:
	go vet ./...

clean:
	rm -f $(BINARY_NAME)

install: build
	cp $(BINARY_NAME) $(GOPATH)/bin/$(BINARY_NAME) 2>/dev/null || \
	cp $(BINARY_NAME) $(HOME)/go/bin/$(BINARY_NAME)
