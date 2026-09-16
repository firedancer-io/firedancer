include src/app/fdctl/version.mk
include src/app/fdctl/with-agave.mk

# Frankendancer versioning is always major 0, the first full Firedancer
# release will be version 1.0
FIREDANCER_VERSION_MAJOR := $(VERSION_MAJOR)

# The minor version is a Firedancer specific version number, indicating
# which release candidate branch this is. Different Firedancer release
# branches could point to the same Agave patch.
# printf "%02d" without a shell
pad2 = $(if $(filter-out 0 1 2 3 4 5 6 7 8 9,$(1)),$(1),0$(or $(1),0))
FIREDANCER_VERSION_MINOR := $(VERSION_MINOR)$(call pad2,$(VERSION_PATCH))

# Agave version v4 encodes the prerelease bits in the minor version.
# We do the same to make sure the prerelease information does not get
# lost.  This is a no-op when the prerelease is Stable == 0.
ifneq ($(AGAVE_PRERELEASE_TAG),0)
FIREDANCER_VERSION_MINOR := $(shell echo $$(( $(FIREDANCER_VERSION_MINOR) | ($(AGAVE_PRERELEASE_TAG) << $(AGAVE_PRERELEASE_BITS_OFFSET)) )) )
endif

# For Frankendancer, we stuff the entire Agave version that we are
# linking to in the patch version.  This transforms, for example, a full
# Agave version of "4.1.7" to a patch version of "40107".  If it is a
# prerelease like "4.1.0-beta.7", we use the prerelease version as the
# agave patch version and the frankendancer patch again becomes "40107"
# (NOT "40100").  The minor version carries the information that it is
# a prerelease even when the patch versions are the same.
FIREDANCER_VERSION_PATCH := $(or $(AGAVE_VERSION_MAJOR),0)$(call pad2,$(AGAVE_VERSION_MINOR))$(call pad2,$(AGAVE_VERSION_PATCH))

export FIREDANCER_VERSION_MAJOR
export FIREDANCER_VERSION_MINOR
export FIREDANCER_VERSION_PATCH

# See src/flamenco/gossip/fd_gossip_message.h
# We adapt that logic to Frankendancer's unique versioning scheme which
# squeezes Agave's version into the patch number
FIREDANCER_VERSION_MINOR_ACTUAL := $(VERSION_MINOR)$(call pad2,$(VERSION_PATCH))
ifneq ($(AGAVE_PRERELEASE_TAG),0)
FIREDANCER_VERSION_CSTR := $(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR_ACTUAL).0-$(AGAVE_PRERELEASE_STRING).$(FIREDANCER_VERSION_PATCH)
else
FIREDANCER_VERSION_CSTR := $(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR).$(FIREDANCER_VERSION_PATCH)
endif
export FIREDANCER_VERSION_CSTR
