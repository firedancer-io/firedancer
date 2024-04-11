# Frankendancer versioning is always major 0, the first full Firedancer
# release will be version 1.0
FIREDANCER_VERSION_MAJOR := 0

# The minor version is a Firedancer specific version number, indicating
# which release candidate branch this is. Different Firedancer release
# branches could point to the same Solana Labs patch.
FIREDANCER_VERSION_MINOR := 0

# For Frankendancer, we stuff the entire Solana Labs version that we are
# linking to in the patch version.  This transforms, for example, a full
# Solana Labs version of "1.17.8" to a minor version of "11708".
FIREDANCER_VERSION_PATCH := $(shell grep -Po "(?<=^version = \").*(?=\")" "solana/Cargo.toml" | awk -F. '{ printf "%d%02d%02d\n", $$1, $$2, $$3 }')

export FIREDANCER_VERSION_MAJOR
export FIREDANCER_VERSION_MINOR
export FIREDANCER_VERSION_PATCH

FIREDANCER_CI_COMMIT=$(shell git rev-parse HEAD)
export FIREDANCER_CI_COMMIT
