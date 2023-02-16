LDFLAGS += $(shell pkg-config --libs libbpf)

FD_HAS_LIBBPF:=1
