ifeq ($(FD_DISABLE_OPTIMIZATION),)
CPPFLAGS+=-D_FORTIFY_SOURCE=2 -fPIC -Wl,-z,now -fstack-protector-strong
else
CPPFLAGS+=-fPIC -Wl,-z,now -fstack-protector-strong
endif
LDFLAGS+=-fPIC
