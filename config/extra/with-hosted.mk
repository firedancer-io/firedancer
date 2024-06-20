CPPFLAGS+=-D_XOPEN_SOURCE=700 -DFD_HAS_HOSTED=1
LDFLAGS+=-z noexecstack -lrt

FD_HAS_HOSTED:=1

UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
FD_HAS_LINUX:=1
endif
