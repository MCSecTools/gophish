TARGET=gophish
VERSION=0.0.2
PACKAGES=core database log parser

.PHONY: all docker clean

all: docker pack

build:
	@echo "Building $(TARGET)..."
	@go build -v -tags netgo -ldflags '-extldflags "-static"' -o ./build/$(TARGET) gophish.go

js:
	@echo "Building JS $(TARGET)..."
	@gulp
	@cp -r ./db/ ./release/
	@cp -r ./static/ ./release/
	@cp -r ./templates/ ./release/
	@echo "building js complete."

pack:
	@echo "Packing $(TARGET)..."
	@echo "Creating ZIP file..."
	@sudo chown -R $(USER):$(USER) release
	-sudo rm $(TARGET)-v${VERSION}-linux-64bit.zip
	@cd ./release && find . -type f -exec zip ../$(TARGET)-v${VERSION}-linux-64bit.zip {} +
	@echo "packaging complete."

clean:
	@echo "Cleaning up..."
	@go clean
	@rm -f $(TARGET)-v${VERSION}-linux-64bit.zip
	@rm -f ./build/$(TARGET)
	@rm -rf ./release/*

docker:
	@echo "Building Docker image..."
	-docker rm -f $(TARGET)-builder
	@mkdir -p release 
	@docker build --progress=plain -t $(TARGET)-builder:$(VERSION) .
	@echo "Running Docker container to generate release..."
	@docker run --name $(TARGET)-builder -v "$(PWD)/release:/gophish/release" $(TARGET)-builder:$(VERSION)
	@docker rm -f $(TARGET)-builder  # Eliminamos el contenedor después de usarlo
	@sudo chown -R $(USER):$(USER) release


