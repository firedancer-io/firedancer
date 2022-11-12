CPPFLAGS+=            \
  -Werror             \
  -Wall               \
  -Wextra             \
  -Wpedantic          \
  -Wstrict-aliasing=2 \
  -Wconversion        \
  -Wdouble-promotion  \
  -Wformat-security

CFLAGS+=  -std=c17
CXXFLAGS+=-std=c++17

ifdef FD_USING_CLANG # CLANG specific

CPPFLAGS+=-Wimplicit-fallthrough

# Extra brutality
#CPPFLAGS+=-Winline
#CPPFLAGS+=-Wproperty-attribute-mismatch

else # GCC specific

CPPFLAGS+=-Wimplicit-fallthrough=2

# Extra brutality
#CPPFLAGS+=-Winline
#CPPFLAGS+=-Wsuggest-attribute=pure
#CPPFLAGS+=-Wsuggest-attribute=const
#CPPFLAGS+=-Wsuggest-attribute=noreturn
#CPPFLAGS+=-Wsuggest-attribute=format

endif

