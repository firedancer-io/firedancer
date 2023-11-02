CPPFLAGS+=-D_FORTIFY_SOURCE=2 -fpie -pie -fPIC -Wl,-z,now -fstack-protector-strong
LDFLAGS+=-fpie -pie -fPIC
