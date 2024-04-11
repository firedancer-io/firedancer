# Only works with Clang.
CPPFLAGS+=-fsanitize=leak
LDFLAGS+=-fsanitize=leak
