# Allows user to replace the default C++ standard library with libc++.
# Useful for building with MSan.
#
# Example setup:
#
#   git clone --depth=1 https://github.com/llvm/llvm-project
#   cd llvm-project
#   cmake -S runtimes -B build -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DLLVM_USE_SANITIZER=MemoryWithOrigins
#   cmake --build build -- cxx cxxabi unwind
#   export LIBCXX=$(pwd)/build

ifndef LIBCXX
$(error LIBCXX is not set)
endif

CPPFLAGS+=-nostdinc++
CPPFLAGS+=-isystem $(LIBCXX)/include
CPPFLAGS+=-isystem $(LIBCXX)/include/c++/v1
LDFLAGS+=-Wl,--rpath=$(LIBCXX)/lib
