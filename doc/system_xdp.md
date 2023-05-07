XDP system installation
=======================

Installation guide for XDP/AF_XDP based networking.

Prerequisites
-------------

This guide assumes the steps in [build.md](./build.md) have been completed.

Requires recent Linux kernel and headers (version >=4.18).
XDP and related technologies are being activiely developed and usually
have noticable improvements in the most recent kernels (>=6.2). (Though,
as always, there are drawbacks with running cutting edge software)

Introduction to XDP and AF_XDP
------------------------------

**What sysadmins should know:**

XDP and AF_XDP are Linux kernel technologies for fast userspace
networking.  They present an alternative to send/recv sockets-based
networking that are generally more efficient and expose lower-level
properties of your hardware to the Firedancer application.

Despite their similar names, there is an important distinction in the
purpose of XDP vs AF_XDP:
- XDP is a facility to redirect traffic away from regular kernel networking.
- AF_XDP is a mechanism for traffic forwarding between
the kernel and userland.

So to put the two together, we install an XDP program to intercept all
incoming traffic on a network interface. This program filters out all
traffic targeted at Firedancer and sends it to AF_XDP. Firedancer then
reads incoming packets from AF_XDP. Packets going out from Firedancer
get sent back to AF_XDP, which forwards directly to the driver (skipping
XDP).

```
  ┌─────┐  ┌────────┐  ┌─────┐ XDP_PASS ┌─────────┐
  │ NIC <──> Driver ├──> XDP ├──────────> sockets │
  └─────┘  └───▲────┘  └─┬───┘          └─────────┘
               │         │
               │         │ XDP_REDIRECT
               │         │
               │      ┌──▼────────┐      ┌────────────┐
               │      │ AF_XDP RX ├──────> Firedancer │
               │      └───────────┘      └─────┬──────┘
               │      ┌───────────┐            │
               └──────┤ AF_XDP TX <────────────┘
                      └───────────┘
```

Additional resources:
- [fd_xsk.h](../src/tango/xdp/fd_xsk.h)
- [fd_xdp_ctl_help](../src/tango/xdp/fd_xdp_ctl_help)

XDP and AF_XDP require root and CAP_SYS_ADMIN privileges for
configuration.  For now, these privileges are also required at runtime,
but this is going to be fixed in the future.

XDP installation
----------------

### Preparation

Confirm your kernel release version.

```
$ uname -sr
Linux 4.18.0-348.23.1.el8_5.x86_64
```

`bpffs` is a file system mount containing the XDP configuration.

Ensure `/sys/fs/bpf` is a valid `bpffs` mount. This is the case for most
modern distributions. If the below command does not produce comparable
output, refer to your operating system's documentation.

```
$ mount | grep /sys/fs/bpf
bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
```

### Installation

As usual, kernel configuration gets reset when the machine is rebooted.
Therefore, the following steps will have to be re-run each reboot.

(This can be automated via systemd)

Initialize a subdirectory in `/sys/fs/bpf` to host Firedancer config
and set appropriate permissions.  In this case, we initialize a BPF dir
called "frank" with permission bits 0750 and set the user and group to
the current user.

```
$ sudo build/linux/gcc/x86_64/bin/fd_xdp_ctl init frank 0750 $USER ""
fd_xdp_redirect_user.c(124): Activated XDP environment at /sys/fs/bpf/frank
fd_xdp_ctl.c(76): 0: init frank 0750 ripatel : success
fd_xdp_ctl.c(358): processed 1 commands
```
