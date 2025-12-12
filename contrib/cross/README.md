# Cross-compiling

Firedancer supports rudimentary cross-compiling to support development.

`contrib/cross` contains scripts like `<HOST>_x_<TARGET>.sh` that set up a
compile toolchain for foreign targets.

For example, `macos-arm-clang_x_linux-x86.sh`:
- sets up an environment on a macOS Arm machine (the most common
  development platform)
- uses the Clang compiler
- produces binaries for Linux x86 (the most common development target)

## Security

The cross-compile setup is neither stable nor secure.  Cross-compiled
binaries may contain bugs or lack security features that a native compile
has.

The cross toolchain sources binary blobs from remote sources without
checksum pinning (currently the Fedora mirror and a cloud storage bucket
hosted by the Firedancer team).  This is done because the cross-compile
environment only intends to compile Firedancer itself, not fully bootstrap
all prerequisites.

## Setup

To begin, run the toolchain setup at `contrib/cross/HOST_x_TARGET.sh`.

```shell
contrib/cross/macos-arm-clang_x_linux-x86.sh
```

This will:
- Prompt the user to install build dependencies via the native package
  manager (e.g. a cross-compile capable Clang)
- Download the target build environment (kernel headers, libc, etc.)
- Download and build Firedancer project dependencies
- Create the `./opt/cross/macos-arm-clang_x_linux-x86` prefix

## Usage

Define `CROSS` and `MACHINE` to reconfigure Firedancer's build system into
cross-compile mode.

Use `gmake` (GNU Make) on macOS instead of the Apple-provided `make`
command.

```
export CROSS=macos-arm-clang_x_linux-x86
export MACHINE=linux_clang_zen2
gmake -j16

# produces build-cross/linux/clang/zen2/...
```
