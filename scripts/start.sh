#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "${1:-}" = "--core-only" ]; then
  docker compose up -d --build app
else
  docker compose --profile tools up -d --build
fi
printf '%s\n' 'Химера: http://localhost:8000'
