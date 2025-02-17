include src/app/fdctl/version.mk

# Frankendancer versioning is always major 0, the first full Firedancer
# release will be version 1.0
FIREDANCER_VERSION_MAJOR := $(VERSION_MAJOR)

# The minor version is a Firedancer specific version number, indicating
# which release candidate branch this is. Different Firedancer release
# branches could point to the same Agave patch.
FIREDANCER_VERSION_MINOR := $(VERSION_MINOR)$(shell printf "%02d" $(VERSION_PATCH))

# For Frankendancer, we stuff the entire Agave version that we are
# linking to in the patch version.  This transforms, for example, a full
# Agave version of "1.18.7" to a minor version of "11807".
FIREDANCER_VERSION_PATCH := $(shell grep -Po "(?<=^version = \").*(?=\")" "agave/Cargo.toml" | awk -F. '{ printf "%d%02d%02d\n", $$1, $$2, $$3 }')

# If the Agave submodule is not checked out, the above command fails
ifeq ($(FIREDANCER_VERSION_PATCH),)
FIREDANCER_VERSION_PATCH := 9999
endif

export FIREDANCER_VERSION_MAJOR
export FIREDANCER_VERSION_MINOR
export FIREDANCER_VERSION_PATCH

FIREDANCER_CI_COMMIT := $(shell git rev-parse HEAD)
export FIREDANCER_CI_COMMIT
