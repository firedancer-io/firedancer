MAY_INCLUDE_BASE=1
include config/base.mk
undefine MAY_INCLUDE_BASE

# security
CPPFLAGS+=-D_FORTIFY_SOURCE=2 -fpie -pie -fPIC -Wl,-z,now -fstack-protector-strong
LDFLAGS+=-fpie -pie -fPIC
