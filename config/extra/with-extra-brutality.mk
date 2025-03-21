ifdef FD_USING_CLANG

CPPFLAGS+=-Wproperty-attribute-mismatch

endif

ifdef FD_USING_GCC

CPPFLAGS+=-Wsuggest-attribute=pure
CPPFLAGS+=-Wsuggest-attribute=const
CPPFLAGS+=-Wsuggest-attribute=noreturn
CPPFLAGS+=-Wsuggest-attribute=format
CPPFLAGS+=-fdiagnostics-color=always

endif
