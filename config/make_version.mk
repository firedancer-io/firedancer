ifndef MAKE_VERSION
$(error This Makefile requires GNU Make 4.2 or newer. Try invoking 'gmake')
endif

_gnumake_version_words := $(subst ., ,$(MAKE_VERSION))
_gnumake_major := $(word 1,$(_gnumake_version_words))
_gnumake_minor := $(word 2,$(_gnumake_version_words))

# Reject GNU Make < 4.2.
ifneq ($(filter 0 1 2 3,$(_gnumake_major)),)
$(error GNU Make 4.2 or newer is required; found GNU Make $(MAKE_VERSION))
endif
ifeq ($(_gnumake_major),4)
ifeq ($(filter-out 0 1,$(_gnumake_minor)),)
$(error GNU Make 4.2 or newer is required; found GNU Make $(MAKE_VERSION))
endif
endif
