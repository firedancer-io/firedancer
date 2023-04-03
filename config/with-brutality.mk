CPPFLAGS+=            \
  -Werror             \
  -Wall               \
  -Wextra             \
  -Wstrict-aliasing=2 \
  -Wdouble-promotion  \
  -Wformat-security

ifdef FD_USING_CLANG

CPPFLAGS+=-Wimplicit-fallthrough

# Extra brutality
#CPPFLAGS+=-Winline
#CPPFLAGS+=-Wproperty-attribute-mismatch

endif

ifdef FD_USING_GCC

CPPFLAGS+=-Wimplicit-fallthrough=2

# Extra brutality
#CPPFLAGS+=-Winline
#CPPFLAGS+=-Wsuggest-attribute=pure
#CPPFLAGS+=-Wsuggest-attribute=const
#CPPFLAGS+=-Wsuggest-attribute=noreturn
#CPPFLAGS+=-Wsuggest-attribute=format

endif
