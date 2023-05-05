#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>

int main(int argc, char **argv) {
    (void)argc;

    struct __user_cap_header_struct capheader;
    struct __user_cap_data_struct capdata[2];

    capheader.version = _LINUX_CAPABILITY_VERSION_3;
    capheader.pid = 0;

    if (syscall(SYS_capget, &capheader, &capdata) < 0) {
        perror("capget");
        return 1;
    }

    capdata[0].inheritable |= (1 << CAP_SYS_NICE) | (1 << CAP_SYS_ADMIN) | (1 << CAP_NET_RAW);

    if (syscall(SYS_capset, &capheader, &capdata) < 0) {
        perror("capset");
        return 1;
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_NICE, 0, 0)) {
        perror("cap raise cap_sys_nice");
        return 1;
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0)) {
        perror("cap raise cap_sys_admin");
        return 1;
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_RAW, 0, 0)) {
        perror("cap raise cap_net_raw");
        return 1;
    }

    char *gdb = "/bin/gdb";
    argv[0] = gdb;

    if (execv(gdb, argv) < 0) {
        perror("execv");
        return 1;
    }

    return 0;
}
