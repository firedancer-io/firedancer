CC:=gcc
BUILDDIR?=native_ffi/$(CC)

include config/machine/native.mk
include config/extra/with-ffi.mk
