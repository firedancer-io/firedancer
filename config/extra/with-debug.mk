CPPFLAGS+=-g3
CPPFLAGS+=-fno-omit-frame-pointer
LDFLAGS+=-rdynamic

# GCC var-tracking is up to ~50% of compile time on big -O3 TUs;
# disabling it only degrades "print <var>" in optimized frames.
ifdef FD_USING_GCC
CPPFLAGS+=-fno-var-tracking
endif
