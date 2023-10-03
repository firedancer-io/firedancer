CPPFLAGS+=            \
  -Werror             \
  -Wall               \
  -Wextra             \
  -Wpedantic          \
  -Wconversion        \
  -Wdouble-promotion  \
  -Wstrict-aliasing=2 \
  -Wno-format

ifdef FD_USING_CLANG

CPPFLAGS+=-Wimplicit-fallthrough

endif

ifdef FD_USING_GCC

CPPFLAGS+=-Wimplicit-fallthrough=2

# Check for GCC version and only warn for -Wdangling-pointer if we are using 
# gcc 13 as it is giving a false positive 
# Note we have to add -Wdangling-pointer as in `with-gcc.mk` we disable the 
# warning entirely
ifeq "$(CC_MAJOR_VERSION)" "13"
CPPFLAGS+=-Wdangling-pointer -Wno-error=dangling-pointer
endif

endif
