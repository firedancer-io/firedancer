CPPFLAGS+=-DFD_FN_PURE="__attribute__((pure))"
CPPFLAGS+=-DFD_FN_CONST="__attribute__((const))"

ifdef FD_USING_CLANG

CPPFLAGS+=-Winline
CPPFLAGS+=-Wproperty-attribute-mismatch

endif

ifdef FD_USING_GCC

CPPFLAGS+=-Winline
CPPFLAGS+=-Wsuggest-attribute=pure
CPPFLAGS+=-Wsuggest-attribute=const
CPPFLAGS+=-Wsuggest-attribute=noreturn
CPPFLAGS+=-Wsuggest-attribute=format
CPPFLAGS+=-fdiagnostics-color=always

endif
