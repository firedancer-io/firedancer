CFLAGS+=-DFD_HAS_LIBBPF=1
LDFLAGS+=$(shell pkg-config --libs libbpf)
CFLAGS+=$(shell pkg-config --cflags libbpf | sed s/-I/-isystem/)
FD_HAS_LIBBPF:=1
