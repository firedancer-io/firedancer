XDP system installation
=======================

Installation guide for `XDP`/`AF_XDP` based networking.

Prerequisites
-------------

This guide assumes the steps in [getting-started.md](./getting-started.md)
have been completed.

Requires recent Linux kernel and headers (version >=4.18). `XDP` and related
technologies are being actively developed and usually have noticeable
improvements in the most recent kernels (>=6.2).

Introduction to `XDP` and `AF_XDP`
------------------------------

**What sysadmins should know:**

`XDP` and `AF_XDP` are Linux kernel technologies for fast userspace
networking.  They present an alternative to `send`/`recv` sockets-based
networking that are generally more efficient and expose lower-level
properties of your hardware to the Firedancer application.

Despite their similar names, there is an important distinction in the
purpose of `XDP` vs `AF_XDP`:
- `XDP` is a facility to redirect traffic away from regular kernel networking.
- `AF_XDP` is a mechanism for traffic forwarding between
the kernel and userland.

So to put the two together, we install an `XDP` program to intercept all
incoming traffic on a network interface. This program filters out all
traffic targeted at Firedancer and sends it to `AF_XDP`. Firedancer then
reads incoming packets from `AF_XDP`. Packets going out from Firedancer
get sent back to `AF_XDP`, which forwards directly to the driver (skipping
`XDP`).

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

`XDP` and `AF_XDP` require the `CAP_SYS_ADMIN` and `CAP_NET_ADMIN`
capabilities for configuration.  `CAP_SYS_ADMIN` is also required at
runtime, but this capability is dropped by sandboxing code once the
socket has been configured.

XDP installation
----------------

### Preparation

Confirm your kernel release version.

```bash
$ uname -sr
Linux 4.18.0-348.23.1.el8_5.x86_64
```

`bpffs` is a file system mount containing the XDP configuration.

Ensure `/sys/fs/bpf` is a valid `bpffs` mount. This is the case for most
modern distributions. If the below command does not produce comparable
output, refer to your operating system's documentation.

```bash
$ mount | grep /sys/fs/bpf
bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
```

### Installation

As usual, kernel configuration gets reset when the machine is rebooted.
Therefore, the following steps will have to be re-run each reboot.

Initialize a subdirectory in `/sys/fs/bpf` to host Firedancer config
and set appropriate permissions.  In this case, we initialize a `BPF` dir
called `firedancer` with permission bits `0750` and set the user  to the
current user.

```bash
$ sudo build/linux/gcc/x86_64/bin/fd_xdp_ctl init firedancer 0750 $USER ""
fd_xdp_redirect_user.c(124): Activated XDP environment at /sys/fs/bpf/firedancer
fd_xdp_ctl.c(76): 0: init firedancer 0750 firedancer : success
fd_xdp_ctl.c(358): processed 1 commands
```
