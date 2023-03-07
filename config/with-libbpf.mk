CFLAGS+=-DFD_HAS_LIBBPF=1 $(shell pkg-config --cflags libbpf | sed s/-I/-isystem/)
LDFLAGS+=$(shell pkg-config --libs libbpf)
FD_HAS_LIBBPF:=1
