#!/bin/bash
set -e

GOOS=js GOARCH=wasm go build -ldflags="-s -w" -gcflags=all=-l -o iutk.wasm

# Embed WASM as data URL into HTML to allow running without a web server.
echo -n 'data:application/wasm;base64,' > iutk.wasm.base64
base64 --wrap=0 iutk.wasm >> iutk.wasm.base64
awk 'BEGIN{getline b < "iutk.wasm.base64"}/WASMURL/{gsub("WASMURL",b)}1' index.html.tmpl > index.html

echo "Build success!"
echo "Now open index.html in your browser."
