include config/linux_clang_x86_64.mk
BUILDDIR:=linux/clang/x86_64_ubsan

FD_HAS_UBSAN:=1
CPPFLAGS+=-DFD_HAS_UBSAN=1

LDFLAGS+=-fsanitize=undefined

CPPFLAGS+=-fsanitize=undefined \
          -fsanitize=shift -fsanitize=shift-exponent -fsanitize=shift-base \
          -fsanitize=integer-divide-by-zero \
          -fsanitize=unreachable \
          -fsanitize=vla-bound \
          -fsanitize=null \
          -fsanitize=return \
          -fsanitize=signed-integer-overflow \
          -fsanitize=bounds \
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

# note that -fsanitize=bounds-strict is not supported by clang 15 \
