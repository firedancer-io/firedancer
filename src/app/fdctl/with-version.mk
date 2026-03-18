include src/app/fdctl/version.mk
include src/app/fdctl/with-agave.mk

# Frankendancer versioning is always major 0, the first full Firedancer
# release will be version 1.0
FIREDANCER_VERSION_MAJOR := $(VERSION_MAJOR)

# The minor version is a Firedancer specific version number, indicating
# which release candidate branch this is. Different Firedancer release
# branches could point to the same Agave patch.
FIREDANCER_VERSION_MINOR := $(VERSION_MINOR)$(shell printf "%02d" $(VERSION_PATCH))

# Agave version v4 encodes the prerelease bits in the minor version.
# We do the same to make sure the prerelease information does not get
# lost.  This is a no-op when the prerelease is Stable == 0.
FIREDANCER_VERSION_MINOR := $(shell echo $$(( $(FIREDANCER_VERSION_MINOR) | ($(AGAVE_PRERELEASE_TAG) << $(AGAVE_PRERELEASE_BITS_OFFSET)) )) )

# For Frankendancer, we stuff the entire Agave version that we are
# linking to in the patch version.  This transforms, for example, a full
# Agave version of "4.1.7" to a patch version of "40107".  If it is a
# prerelease like "4.1.0-beta.7", we use the prerelease version as the
# agave patch version and the frankendancer patch again becomes "40107"
# (NOT "40100").  The minor version carries the information that it is
# a prerelease even when the patch versions are the same.
FIREDANCER_VERSION_PATCH := $(shell printf "%d%02d%02d" $(AGAVE_VERSION_MAJOR) $(AGAVE_VERSION_MINOR) $(AGAVE_VERSION_PATCH))

export FIREDANCER_VERSION_MAJOR
export FIREDANCER_VERSION_MINOR
export FIREDANCER_VERSION_PATCH

FIREDANCER_CI_COMMIT := $(shell git rev-parse HEAD)
export FIREDANCER_CI_COMMIT
