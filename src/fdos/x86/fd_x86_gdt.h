#ifndef HEADER_fd_src_fdos_x86_fd_x86_gdt_h
#define HEADER_fd_src_fdos_x86_fd_x86_gdt_h

#include "../../util/fd_util_base.h"

union __attribute__((packed)) fd_x86_gdt {
  struct __attribute__((packed)) {
    ushort limit0;
    ushort base0;
    ushort base1 : 8;
    ushort type : 4;
    ushort s : 1;
    ushort dpl : 2;
    ushort p : 1;
    ushort limit1 : 4;
    ushort avl : 1;
    ushort l : 1;
    ushort d : 1;
    ushort g : 1;
    ushort base2 : 8;
  };
  struct __attribute__((packed)) {
    uint base3;
    uint reserved;
  };
  ulong ul;
};

typedef union fd_x86_gdt fd_x86_gdt_t;

#endif /* HEADER_fd_src_fdos_x86_fd_x86_gdt_h */
