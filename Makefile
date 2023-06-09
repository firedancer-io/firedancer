# Basic usage:
#
#  make -j
#
# will do a parallel make all targets for the native machine.
#
# If a default compiler is not specified with CC=clang or CC=gcc,
# gcc will be used.  The features of the compiler and host machine
# are automatically detected.
#
# The environment variable EXTRAS allows enabling optional build
# features in config/with-*.mk.  For example:
#
#  make -j EXTRAS="ffi"
#
# would enable the "with-ffi.mk" config.
#
#  make help
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

$(info Using EXTRAS=$(EXTRAS))

include config/native.mk
include $(addprefix config/with-,$(addsuffix .mk,$(EXTRAS)))
include config/everything.mk
include config/coverage.mk
