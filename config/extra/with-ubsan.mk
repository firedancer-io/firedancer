# Note: This probably needs to after machine specific targets otherwise
# the -fomit-frame-pointer that occurs there will be silently override
# the -fno-omit-frame-pointer here.

FD_HAS_UBSAN:=1
CPPFLAGS+=-DFD_HAS_UBSAN=1

FD_UNALIGNED_ACCESS_STYLE:=0
CPPFLAGS+=-DFD_UNALIGNED_ACCESS_STYLE=0

LDFLAGS+=-fsanitize=undefined
# UBSan runtime uses C++ RTTI
LDFLAGS+=-lstdc++

CPPFLAGS+=-fsanitize=undefined \
          -fsanitize=shift -fsanitize=shift-exponent -fsanitize=shift-base \
          -fsanitize=integer-divide-by-zero \
          -fsanitize=unreachable \
          -fsanitize=vla-bound \
          -fsanitize=null \
          -fsanitize=return \
          -fsanitize=bounds \
          -fno-sanitize=signed-integer-overflow \
          -fsanitize=alignment \
          -fsanitize=object-size \
          -fsanitize=float-divide-by-zero \
          -fsanitize=float-cast-overflow \
          -fsanitize=nonnull-attribute \
          -fsanitize=returns-nonnull-attribute \
          -fsanitize=bool \
          -fsanitize=enum \
          -fsanitize=vptr \
          -fsanitize=pointer-overflow \
          -fsanitize=builtin

# base.mk's -fno-strict-overflow implies -fwrapv-pointer on Clang 20+,
# which turns -fsanitize=pointer-overflow off.  Clang takes the last of
# the two flags, so this goes in CFLAGS, after base.mk's.  Clang <20
# does not know -fwrapv-pointer, and GCC keeps the check either way.
ifdef FD_USING_CLANG
ifeq ($(shell test $(CC_MAJOR_VERSION) -ge 20 2>/dev/null && echo yes),yes)
CFLAGS+=-fno-wrapv-pointer
endif
endif
