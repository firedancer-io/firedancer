CFLAGS+=-DFD_HAS_LIBBPF=1
CFLAGS+=$(shell pkg-config --cflags libbpf)
LDFLAGS+=$(shell pkg-config --libs libbpf)
FD_HAS_LIBBPF:=1
