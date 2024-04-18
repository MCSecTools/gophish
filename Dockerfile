# Use a single multi-stage build process to handle both the JavaScript assets and the Go binary

# Base image for building
FROM debian:bookworm-slim AS builder

# Install required tools for Node.js, Golang builds, and general build tools
RUN apt-get update && apt-get install -y \
    curl \
    golang-go \
    make \
    zip

# Install Node.js and npm
# Debian's default repos might not have the latest Node.js, using NodeSource or similar might be better
#RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
#RUN apt-get install -y nodejs

# Optionally install Gulp globally if needed
#RUN npm install gulp gulp-cli -g

# Clean up to keep the image clean and compact
RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy the entire source directory (assuming it includes the Makefile, and source files for Node and Go)
COPY . /gophish

# Set the working directory for all the subsequent operations
WORKDIR /gophish

# Run npm install and gulp as per the Makefile's build steps for JS assets
# Assuming you have a package.json and gulp is part of your workflow
#RUN npm install
#RUN gulp

# Run the Makefile build step to handle Go compilation and any additional packaging defined in the Makefile
RUN go get -v

RUN make build

RUN go build -v -tags netgo -ldflags '-extldflags "-static"' -o ./build/gophish gophish.go

COPY release.sh release.sh
RUN chmod +x release.sh
# build
ENTRYPOINT ["./release.sh"]
