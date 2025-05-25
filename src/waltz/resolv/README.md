# fd_resolv

The purpose of this module is to provide a Linux userland DNS resolver
for servers on a WAN.  Syscalls and file system accesses are precisely
documented to facilitate seccomp and landlock sandboxing.  Not optimized
for performance.

This module is a modified copy of the getaddrinfo implementation from
musl libc.  It was imported circa 2025-May.

## Modifications

- Aligned with Firedancer's code style
  - General code formatting
  - Rewrote in C17 style (moved variable declarations to definitions)
- Modified to pass strict compiler diagnostics
- Removed pthread cancellation support
- Removed pthread cleanup API usages
- Replaced internal musl API usages with public libc variants
- Removed malloc calls
- Removed support for search domains
- Removed unused code incurred by keeping API compatibility.
- Replaced stdio.h (fopen, fgets, etc) with fd_io`
- Reuses /etc/hosts and /etc/resolv.conf file descriptors for better
  sandboxing.

## Copyright

See /NOTICE
