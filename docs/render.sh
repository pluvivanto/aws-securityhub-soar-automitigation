#!/bin/sh
set -e
cd "$(dirname "$0")/.."
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/src" -w /src d2lang/d2:latest --layout tala docs/architecture.d2 docs/architecture.svg
