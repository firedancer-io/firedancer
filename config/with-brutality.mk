CPPFLAGS+=                 \
  -Werror                  \
  -Wall                    \
  -Wextra                  \
  -Wpedantic               \
  -Wstrict-aliasing=2      \
  -Wimplicit-fallthrough=2 \
  -Wconversion             \
  -Wdouble-promotion       \
  -Wformat-security

CFLAGS+=  -std=c17
CXXFLAGS+=-std=c++17

# Extra brutality
# CPPFLAGS+=-Winline
# CPPFLAGS+=-Wsuggest-attribute=pure
# CPPFLAGS+=-Wsuggest-attribute=const
# CPPFLAGS+=-Wsuggest-attribute=noreturn
# CPPFLAGS+=-Wsuggest-attribute=format

