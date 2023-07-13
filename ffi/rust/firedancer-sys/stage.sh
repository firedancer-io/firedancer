#!/bin/bash
#
# Prepare staging directory for CI environment so `cargo package`
# works.
set -xeuo

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "${SCRIPT_DIR}"
mkdir -p "${PWD}/staging"
cd "${PWD}/staging"
ln -s ../../../../Makefile Makefile
ln -s ../../../../config config
ln -s ../../../../src src
