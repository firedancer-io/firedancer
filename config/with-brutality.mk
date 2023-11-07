CPPFLAGS+=            \
  -Werror             \
  -Wall               \
  -Wextra             \
  -Wpedantic          \
  -Wstrict-aliasing=2 \
  -Wconversion        \
  -Wdouble-promotion  \
  -Wno-format

ifdef FD_USING_CLANG
CPPFLAGS+=-Wimplicit-fallthrough
endif

ifdef FD_USING_GCC
CPPFLAGS+=-Wimplicit-fallthrough=2
CFLAGS+=-Wstrict-prototypes
endif
