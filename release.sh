#!/bin/bash

mkdir -p ./release/
mkdir -p ./build/
go build -v -tags netgo -ldflags '-extldflags "-static"' -o ./build/gophish gophish.go
cp ./build/gophish ./release/gophish
cp -r ./db/ /gophish/release/
cp -r ./static/ /gophish/release/
cp -r ./templates/ /gophish/release/
echo ls -la /gophish/release/
ls -la /gophish/release/
chmod 744 -R ./release/