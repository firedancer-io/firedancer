CPPFLAGS+=            \
  -Werror             \
  -Wall               \
  -Wextra             \
  -Wpedantic          \
  -Wstrict-aliasing=2 \
  -Wconversion        \
  -Wdouble-promotion  \
  -Wformat-security

ifdef FD_USING_CLANG
CPPFLAGS+=-Wimplicit-fallthrough
# See with-clang.mk
CPPFLAGS+=-Wno-address-of-packed-member -Wno-unused-command-line-argument -Wno-bitwise-instead-of-logical
endif

ifdef FD_USING_GCC
CPPFLAGS+=-Wimplicit-fallthrough=2
CFLAGS+=-Wstrict-prototypes
endif
