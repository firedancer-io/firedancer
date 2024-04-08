#!/usr/bin/env bash
set -e

mount bpffs /sys/fs/bpf -t bpf
mount --make-shared /sys/fs/bpf
sed -i 's~^user.*$~user = "firedancer"~' /opt/firedancer/config/default.toml

exec "$@"
