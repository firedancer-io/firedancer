FD_ON_MACOS:=1
CPPFLAGS+=-D__MAC_OS_X_VERSION_MIN_REQUIRED=1070

# brew install llvm
LLVM_DIR?=/usr/local/opt/llvm
