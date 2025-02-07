include config/extra/with-handholding.mk
include config/extra/with-asserts.mk

CPPFLAGS+=-g
CPPFLAGS+=-fno-omit-frame-pointer
LDFLAGS+=-rdynamic