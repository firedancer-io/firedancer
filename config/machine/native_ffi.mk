CC:=gcc
BUILDDIR?=native_ffi/$(CC)

include config/native.mk
include config/extra/with-ffi.mk
