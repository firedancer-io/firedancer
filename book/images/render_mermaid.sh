#!/usr/bin/env bash

set -e

# npm install -g @mermaid-js/mermaid-cli

command -v mmdc >/dev/null 2>&1 || { echo "mmdc not found. Install with: npm install -g @mermaid-js/mermaid-cli" >&2; exit 1; }

cd "$(dirname "$0")"
shopt -s nullglob
for input in *.mermaid; do
  mmdc -i "${input}" -o "${input%.mermaid}.svg" -t dark -b transparent
done
