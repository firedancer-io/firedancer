#!/usr/bin/env bash
set -e

sed -i 's~^user.*$~user = "firedancer"~' /opt/firedancer/config/default.toml

exec "$@"
