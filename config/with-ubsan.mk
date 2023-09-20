# Note: This probably needs to after machine specific targets otherwise
# the -fomit-frame-pointer that occurs there will be silently override
# the -fno-omit-frame-pointer here.

FD_HAS_UBSAN:=1
CPPFLAGS+=-DFD_HAS_UBSAN=1

FD_UNALIGNED_ACCESS_STYLE:=0
CPPFLAGS+=-DFD_UNALIGNED_ACCESS_STYLE=0

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
