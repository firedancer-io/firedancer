# Basic usage:
#
#  make -j
#
# will do a parallel make all targets for the native machine.
#
# The environment variable MACHINE allows building for different
# machines.  As such, the above is equivalent to running:
#
#  MACHINE=[default_machine] make -j
#
# where [default_machine] is specified below.  Likewise:
#
#  MACHINE=my_machine make -j
#
# would build for the machine "my_machine".  The detailed configuration
# of the build for this machine would be specified in the file:
#
#  config/my_machine.mk
#
# The environment variable EXTRAS allows enabling optional build
# features in config/with-*.mk.  For example:
#
#  make -j EXTRAS="debug"
#
# would enable the "with-debug.mk" config.
#
# Build binaries, unit tests, libraries, headers, other build artifacts
# will be in the directory specified by that file.  As such, builds for
# multiple machine can coexist concurrently.  Typically, targeting a
# build at a new machine can be done by just writing up an appropriate
# machine description.
#
#  MACHINE=my_machine make help
#
# will print out help for the make (targets available for cleaning the
# build for the particular machine, cleaning all builds, generating
# preprocessor outputs, generating asm outputs, generating dependencies,
# etc) and the detailed configuration of the build for that machine.
#
# Note if you have kernel CPU isolation enabled on the build host
# (e.g. isolcpus in the kernel command line), make will typically only
# use non-isolated CPUs for the build (even if you explicitly specify to
# use more cores with -j[N]).  See the "make-j" script in contrib for
# help building efficiently on systems with cpu isolation enabled.

ifndef MACHINE
MACHINE=native
endif

$(info Using MACHINE=$(MACHINE))
$(info Using EXTRAS=$(EXTRAS))

# Default target
all:

define _include-extra
include $(addprefix config/with-,$(addsuffix .mk,$(1)))
endef

include config/$(MACHINE).mk
$(foreach extra,$(EXTRAS),$(eval $(call _include-extra,$(extra))))
include config/everything.mk
include config/coverage.mk
