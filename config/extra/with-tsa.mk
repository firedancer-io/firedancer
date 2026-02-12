ifdef FD_USING_CLANG
# Older versions have no TSA support or false positives.
ifeq ($(shell test $(CC_MAJOR_VERSION) -ge 18 && echo yes),yes)
CPPFLAGS+=-Wthread-safety
else
$(error EXTRAS=tsa requires clang >= 18 (detected CC=$(CC), version $(CC_MAJOR_VERSION)))
endif
else
$(error EXTRAS=tsa requires clang >= 18 (detected CC=$(CC)); GCC/other compilers are unsupported)
endif
