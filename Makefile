TARGET=gophish
VERSION=0.0.2
PACKAGES=core database log parser

.PHONY: all build clean
all: build

build:
	@echo "Building $(TARGET)..."
	@go build -tags netgo -ldflags '-extldflags "-static"' -o ./build/$(TARGET) gophish.go
	@echo "Copying files..."
	@mkdir -p ./release/
	@cp -r ./db/ ./release/
	@cp -r ./static/ ./release/
	@cp -r ./templates/ ./release/
	@cp ./build/$(TARGET) ./release/$(TARGET)
	@echo "Creating ZIP file..."
	@cd ./release && find . -type f -exec zip ../$(TARGET)-v${VERSION}-linux-64bit.zip {} +
	@echo "Build and packaging complete."

clean:
	@echo "Cleaning up..."
	@go clean
	@rm -f $(TARGET)-v${VERSION}-linux-64bit.zip
	@rm -f ./build/$(TARGET)
	@rm -rf ./release/*
