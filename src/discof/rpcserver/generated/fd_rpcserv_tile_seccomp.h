/* THIS FILE WAS GENERATED BY generate_filters.py. DO NOT EDIT BY HAND! */
#ifndef HEADER_fd_src_discof_rpcserver_generated_fd_rpcserv_tile_seccomp_h
#define HEADER_fd_src_discof_rpcserver_generated_fd_rpcserv_tile_seccomp_h

#include "../../../../src/util/fd_util_base.h"
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stddef.h>

#if defined(__i386__)
# define ARCH_NR  AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR  AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define ARCH_NR AUDIT_ARCH_AARCH64
#else
# error "Target architecture is unsupported by seccomp."
#endif
static const unsigned int sock_filter_policy_fd_rpcserv_tile_instr_cnt = 45;

static void populate_sock_filter_policy_fd_rpcserv_tile( ulong out_cnt, struct sock_filter * out, unsigned int logfile_fd, unsigned int rpcserv_socket_fd ) {
  FD_TEST( out_cnt >= 45 );
  struct sock_filter filter[45] = {
    /* Check: Jump to RET_KILL_PROCESS if the script's arch != the runtime arch */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, arch ) ) ),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 0, /* RET_KILL_PROCESS */ 41 ),
    /* loading syscall number in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, nr ) ) ),
    /* allow write based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_write, /* check_write */ 7, 0 ),
    /* allow fsync based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_fsync, /* check_fsync */ 10, 0 ),
    /* allow accept4 based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_accept4, /* check_accept4 */ 11, 0 ),
    /* allow read based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_read, /* check_read */ 18, 0 ),
    /* allow sendto based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto, /* check_sendto */ 23, 0 ),
    /* allow close based on expression */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_close, /* check_close */ 28, 0 ),
    /* simply allow ppoll */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_ppoll, /* RET_ALLOW */ 34, 0 ),
    /* none of the syscalls matched */
    { BPF_JMP | BPF_JA, 0, 0, /* RET_KILL_PROCESS */ 32 },
//  check_write:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 2, /* RET_ALLOW */ 31, /* lbl_1 */ 0 ),
//  lbl_1:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, /* RET_ALLOW */ 29, /* RET_KILL_PROCESS */ 28 ),
//  check_fsync:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, /* RET_ALLOW */ 27, /* RET_KILL_PROCESS */ 26 ),
//  check_accept4:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, rpcserv_socket_fd, /* lbl_2 */ 0, /* RET_KILL_PROCESS */ 24 ),
//  lbl_2:
    /* load syscall argument 1 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 0, /* lbl_3 */ 0, /* RET_KILL_PROCESS */ 22 ),
//  lbl_3:
    /* load syscall argument 2 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 0, /* lbl_4 */ 0, /* RET_KILL_PROCESS */ 20 ),
//  lbl_4:
    /* load syscall argument 3 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SOCK_CLOEXEC|SOCK_NONBLOCK, /* RET_ALLOW */ 19, /* RET_KILL_PROCESS */ 18 ),
//  check_read:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 2, /* RET_KILL_PROCESS */ 16, /* lbl_5 */ 0 ),
//  lbl_5:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, /* RET_KILL_PROCESS */ 14, /* lbl_6 */ 0 ),
//  lbl_6:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, rpcserv_socket_fd, /* RET_KILL_PROCESS */ 12, /* RET_ALLOW */ 13 ),
//  check_sendto:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 2, /* RET_KILL_PROCESS */ 10, /* lbl_7 */ 0 ),
//  lbl_7:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, /* RET_KILL_PROCESS */ 8, /* lbl_8 */ 0 ),
//  lbl_8:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, rpcserv_socket_fd, /* RET_KILL_PROCESS */ 6, /* RET_ALLOW */ 7 ),
//  check_close:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 2, /* RET_KILL_PROCESS */ 4, /* lbl_9 */ 0 ),
//  lbl_9:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, /* RET_KILL_PROCESS */ 2, /* lbl_10 */ 0 ),
//  lbl_10:
    /* load syscall argument 0 in accumulator */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, rpcserv_socket_fd, /* RET_KILL_PROCESS */ 0, /* RET_ALLOW */ 1 ),
//  RET_KILL_PROCESS:
    /* KILL_PROCESS is placed before ALLOW since it's the fallthrough case. */
    BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS ),
//  RET_ALLOW:
    /* ALLOW has to be reached by jumping */
    BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_ALLOW ),
  };
  fd_memcpy( out, filter, sizeof( filter ) );
}

#endif
