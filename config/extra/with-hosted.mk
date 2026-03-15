CPPFLAGS+=-D_XOPEN_SOURCE=700 -DFD_HAS_HOSTED=1
ifneq ($(MACHINE),apple_silicon)
LDFLAGS+=-z noexecstack -lrt
endif

FD_HAS_HOSTED:=1

UNAME?=$(shell uname)
ifeq ($(UNAME), Linux)
FD_HAS_LINUX:=1
endif
