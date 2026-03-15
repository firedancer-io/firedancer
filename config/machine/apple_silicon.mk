# Firedancer machine configuration for Apple Silicon (M4 Max)

# We use Clang by default on macOS
CC=clang
CXX=clang++
LD=clang++

# Machine-specific directories
BUILDDIR?=apple_silicon/$(notdir $(CC))

include config/base.mk
include config/extra/with-clang.mk
include config/extra/with-brutality.mk
include config/extra/with-optimization.mk
include config/extra/with-debug.mk
include config/extra/with-security.mk
include config/extra/with-threads.mk

# Basic hosted/thread support
FD_HAS_HOSTED:=1
FD_HAS_THREADS:=1
FD_HAS_ALLOCA:=1
CPPFLAGS+=-DFD_HAS_HOSTED=1
CPPFLAGS+=-DFD_HAS_THREADS=1
CPPFLAGS+=-DFD_HAS_ALLOCA=1

# Architecture support (ARM64)
FD_HAS_ARM:=1
FD_HAS_INT128:=1
FD_HAS_DOUBLE:=1
CPPFLAGS+=-DFD_HAS_ARM=1
CPPFLAGS+=-DFD_HAS_INT128=1
CPPFLAGS+=-DFD_HAS_DOUBLE=1

# M4 Max Specific Tuning (march=native should work for Clang on macOS)
CPPFLAGS+=-march=native
RUSTFLAGS+=-C target-cpu=native

# macOS Specific Flags
CPPFLAGS+=-D__MACH__=1
CPPFLAGS+=-D_DARWIN_C_SOURCE
CPPFLAGS+=-Wno-format

# Informational
$(info Using MACHINE=apple_silicon)
$(info Using FD_HAS_ARM=1)
$(info Using FD_HAS_THREADS=1)
