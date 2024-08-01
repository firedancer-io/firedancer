CPPFLAGS+=-fPIC
LDFLAGS+=-fPIC

CPPFLAGS+=-Wl,-z,relro,-z,now
LDFLAGS+=-Wl,-z,relro,-z,now

CPPFLAGS+=-fstack-protector-strong
LDFLAGS+=-fstack-protector-strong

# _FORTIFY_SOURCE only works when optimization is enabled
ifeq ($(FD_DISABLE_OPTIMIZATION),)
CPPFLAGS+=-D_FORTIFY_SOURCE=2
endif
