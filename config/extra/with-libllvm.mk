FD_HAS_LIBLLVM:=1
CPPFLAGS+=-DFD_HAS_LIBLLVM=1

CXXFLAGS+=$(shell llvm-config --cxxflags)
LDFLAGS+=$(shell llvm-config --ldflags)
LDFLAGS+=$(shell llvm-config --libs mcdisassembler x86)
