include config/extra/with-asan.mk

FD_HAS_DEEPASAN:=1
CPPFLAGS+=-DFD_HAS_DEEPASAN=1 -fno-omit-frame-pointer
