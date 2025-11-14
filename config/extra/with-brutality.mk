CPPFLAGS+=              \
  -Werror               \
  -Wall                 \
  -Wextra               \
  -Wpedantic            \
  -Wstrict-aliasing=2   \
  -Wconversion          \
  -Wdouble-promotion    \
  -Wformat-security

ifdef FD_USING_CLANG
CPPFLAGS+=-Wimplicit-fallthrough
# See with-clang.mk
CPPFLAGS+=-Wno-address-of-packed-member -Wno-unused-command-line-argument -Wno-bitwise-instead-of-logical
CPPFLAGS+=-Wno-gnu-zero-variadic-macro-arguments

# older clang versions have with clean attributes
ifneq ($(strip $(FD_COMPILER_MAJOR_VERSION)),)
  ifeq ($(shell test $(FD_COMPILER_MAJOR_VERSION) -ge 18 && echo 1),1)
    CPPFLAGS+=-Wthread-safety
  endif
endif
endif

ifdef FD_USING_GCC
CPPFLAGS+=-Wimplicit-fallthrough=2
CFLAGS+=-Wstrict-prototypes
# -Wformat-signedness is supported since GCC 5.1, and since clang 19, however we build on clang 15
CFLAGS+=-Wformat-signedness
endif
