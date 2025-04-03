#!/usr/bin/env bash
set -euo pipefail

VERSION_MK="src/app/fdctl/version.mk"

usage() {
  echo "Usage: $0 [major|minor|patch]"
  exit 1
}

bump_type="${1:-patch}"

read_versions() {
  VERSION_MAJOR=$(awk -F ':=' '/^VERSION_MAJOR/ { print $2 }' "$VERSION_MK" | xargs)
  VERSION_MINOR=$(awk -F ':=' '/^VERSION_MINOR/ { print $2 }' "$VERSION_MK" | xargs)
  VERSION_PATCH=$(awk -F ':=' '/^VERSION_PATCH/ { print $2 }' "$VERSION_MK" | xargs)

  if [[ -z "$VERSION_MAJOR" || -z "$VERSION_MINOR" || -z "$VERSION_PATCH" ]]; then
    echo "Error: Could not read version.mk properly"
    exit 1
  fi
}

bump_version() {
  case "$bump_type" in
    major)
      VERSION_MAJOR=$((VERSION_MAJOR + 1))
      VERSION_MINOR=0
      VERSION_PATCH=0
      ;;
    minor)
      VERSION_MINOR=$((VERSION_MINOR + 1))
      VERSION_PATCH=0
      ;;
    patch)
      VERSION_PATCH=$((VERSION_PATCH + 1))
      ;;
    *)
      echo "Unknown bump type: $bump_type"
      usage
      ;;
  esac
}

write_version_mk() {
  {
    echo "VERSION_MAJOR := $VERSION_MAJOR"
    echo "VERSION_MINOR := $VERSION_MINOR"
    echo "VERSION_PATCH := $VERSION_PATCH"
  } > "$VERSION_MK"
}

main() {
  read_versions
  bump_version
  write_version_mk

  echo "Bumped version to: $VERSION_MAJOR.$VERSION_MINOR.$VERSION_PATCH"
}

main
