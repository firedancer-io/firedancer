#!/usr/bin/env bash

# Note: This is intended for use in GitHub Actions builds only.

export DEBIAN_FRONTEND="noninteractive"
sudo apt install -y --no-install-recommends \
  libelf-dev \
  lcov
