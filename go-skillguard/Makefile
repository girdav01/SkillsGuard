.PHONY: build test clean run fmt vet

BINARY_NAME=skillguard
BUILD_DIR=bin

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/skillguard

test:
	go test ./... -v -count=1

test-short:
	go test ./... -short -count=1

clean:
	rm -rf $(BUILD_DIR)

run: build
	$(BUILD_DIR)/$(BINARY_NAME)

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet
