# These constants should match the Agave rust source code
# agave/version/src/v4.rs
AGAVE_IDENTIFIER_ALPHA := alpha
AGAVE_IDENTIFIER_BETA  := beta
AGAVE_IDENTIFIER_RELEASE_CANDIDATE := rc
AGAVE_ENCODE_TAG_ALPHA := 3
AGAVE_ENCODE_TAG_BETA  := 2
AGAVE_ENCODE_TAG_RELEASE_CANDIDATE := 1
AGAVE_ENCODE_TAG_STABLE := 0
AGAVE_PRERELEASE_BITS_OFFSET := 14

AGAVE_PRERELEASE_TAG := $(AGAVE_ENCODE_TAG_STABLE)

# get the agave version
AGAVE_VERSION := $(shell $(GREP) -Po "(?<=^version = \").*(?=\")" "agave/Cargo.toml")
# If the Agave submodule is not checked out, the above command fails
ifeq ($(AGAVE_VERSION),)
AGAVE_VERSION := 9.9.99
endif

# parse the agave semver
SEMVER_VERSION := $(firstword $(subst -, ,$(AGAVE_VERSION)))
AGAVE_VERSION_MAJOR := $(word 1,$(subst ., ,$(SEMVER_VERSION)))
AGAVE_VERSION_MINOR := $(word 2,$(subst ., ,$(SEMVER_VERSION)))
AGAVE_VERSION_PATCH := $(word 3,$(subst ., ,$(SEMVER_VERSION)))

# try to parse the prerelease version
SEMVER_PRERELEASE := $(word 2,$(subst -, ,$(AGAVE_VERSION)))
ifneq ($(SEMVER_PRERELEASE),)
  AGAVE_PRERELEASE_STRING  := $(word 1,$(subst ., ,$(SEMVER_PRERELEASE)))
  AGAVE_PRERELEASE_VERSION := $(word 2,$(subst ., ,$(SEMVER_PRERELEASE)))
endif

# if this is a prerelease, update the patch and set the tag
ifneq ($(AGAVE_PRERELEASE_STRING),)
  AGAVE_VERSION_PATCH := $(AGAVE_PRERELEASE_VERSION)
  ifeq ($(AGAVE_PRERELEASE_STRING),$(AGAVE_IDENTIFIER_RELEASE_CANDIDATE))
    AGAVE_PRERELEASE_TAG := $(AGAVE_ENCODE_TAG_RELEASE_CANDIDATE)
  else ifeq ($(AGAVE_PRERELEASE_STRING),$(AGAVE_IDENTIFIER_BETA))
    AGAVE_PRERELEASE_TAG := $(AGAVE_ENCODE_TAG_BETA)
  else ifeq ($(AGAVE_PRERELEASE_STRING),$(AGAVE_IDENTIFIER_ALPHA))
    AGAVE_PRERELEASE_TAG := $(AGAVE_ENCODE_TAG_ALPHA)
  endif
endif
