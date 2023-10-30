# Initializing

## Overview
The `fdctl configure` command is used to setup the host environment so
Firedancer can run correctly. It should be run each and every time
before the validator is started, and also should be rerun if the
configuration file changes, even if the validator has not yet been
started.

::: warning WARNING

Configuring the system for Firedancer has many moving parts and you
should prefer to run `fdctl configure init all` if possible. The stages
are described here in detail for advanced use cases and operators only.

:::

The configure command is run like `fdctl configure <mode> <stage>...`
where `mode` is one of:

 - `init` Configures the provided stages if they are not already
   configured.
 - `check` Check if each stage is already configured. The command will
   exit with an error code if they are not. `check` never requires 
   privileges and will not make any changes to the system.
 - `fini` Unconfigure (reverse) the stage if it is reversible.

`stage` can be one or more of `large-pages`, `shmem`, `sysctl`, `xdp`,
`xdp-leftover`, `ethtool`, `workspace-leftover`, or `workspace` and
these stages are described below. You can also use the stage `all`
which will configure everything.

Stages have different privilege requirements, which you can see by
trying to run the stage without privileges. The `check` mode never
requires privileges, and the `init` mode will only require
privileges if it needs to actually change something.

## large-pages
The `large-pages` stage is used to reserve `huge` (2MiB) and `gigantic`
(1GiB) memory pages from the Linux kernel. See also the [kernel
documentation](https://docs.kernel.org/admin-guide/mm/hugetlbpage.html)
of these pages. Almost all memory in Firedancer is allocated out of
these pages for performance reasons.

Firedancer calculates the number of each page kind it needs to run the
validator, and will then tell the kernel to reserve these pages by
writing the number to a file like
`/sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages`.
You can see how many pages will be reserved by running the `fdctl mem`
command.

This stage requires root privileges, and cannot be performed with
capabilities. If the minimum required pages are already reserved, the
`init` mode does nothing and the `check` mode will return successfully
without requiring privileges. The `fini` mode always does nothing and
will not decrease the reserved page count.

::: tip TIP

The `large-pages` step should be run immediately when the system is
booted. If run later, it may fail because the operating system memory is
fragmented and a large contiguous block cannot be reserved.

:::

## shmem
The `shmem` step must be run after `large-pages`, and mounts a gigantic
page filesystem at `/mnt/.fd/.gigantic/` and a huge page filesystem at
`/mnt/.fd/.huge`. These paths can be configured in the TOML file under
the `[shmem]` section. Lets run it:

<<< @/snippets/shmem.ansi

If the correct `hugetlbfs` filesystems have already been mounted at the
right locations, the `init` mode will do nothing and Firedancer will use
the pre-existing mounts. The `check` mode will return successfully
without requiring privileges. Mounts should be large enough to fit the
memory needed by Firedancer, which you can see by running the `fdctl
mem` command.

The `fini` mode will unmount the two filesystems, and remove them from
`/mnt/.fd/`, although it will leave the `/mnt/.fd/` directory in place.
The `fini` mode will not succeed if memory from the mounts is mapped
into a running process.

This stage requires root privileges, and cannot be performed with
capabilities.

## sysctl
It is suggested to run Firedancer with certain kernel parameters tuned
for best performance. The `sysctl` stage will check and configure these
parameters. The stage will only increase values to meet the minimum, and
will not decrease them if the minimum is already met.

| Sysctl                            | Minimum     | Description
| --------------------------------- | ----------- | -----------
| /proc/sys/net/core/rmem_max       | 134217728   | Solana Labs network performance tuning.
| /proc/sys/net/core/rmem_default   | 134217728   | Solana Labs network performance tuning.
| /proc/sys/net/core/wmem_max       | 134217728   | Solana Labs network performance tuning.
| /proc/sys/net/core/wmem_default   | 134217728   | Solana Labs network performance tuning.
| /proc/sys/vm/max_map_count        | 1000000     | Solana Labs accounts database requires mapping many files.
| /proc/sys/net/core/bpf_jit_enable | 1           | Firedancer uses BPF for kernel bypass networking. BPF JIT makes this faster.

The `init` mode requires either `root` privileges, or to be run with
`CAP_SYS_ADMIN`. The `fini` mode does nothing and kernel parameters
will never be reduced as a result of running `configure`.

## xdp
Firedancer uses XDP (express data path), a Linux feature for doing high
performance kernel bypass networking. For more background see the
[kernel
documentation](https://www.kernel.org/doc/html/next/networking/af_xdp.html).

To configure XDP, a BPF program is loaded onto both the configured
network interface `[tiles.net.interface]` and the loopback interface
`lo`. This BPF program intercepts packets matching a Firedancer listen
port before they reach the kernel. Matching packets are routed directly
to Firedancer.

::: warning 

Packets intercepted by the BPF program will not appear under standard
network monitoring tools like `tcpdump`.

:::

The BPF program is loaded into `/sys/fs/bpf/<name>/` and will remain
loaded until `fini` is run. If loaded, packets for the target ports will
be intercepted even when Firedancer itself is not running. `fini` will
fully unload the program, packets for the target ports will resume being
routed to the kernel and regular networking stack.

This stage must be run, and it is not possible to manually configure it.
The stage not only loads the program, but sets up special configuration
objects (BPF maps) so that it functions correctly.

The stage must be rerun any time the system is rebooted, any time
Firedancer is updated, or any time the configuration file changes. The
`init` mode requires `root` or both `CAP_SYS_ADMIN` and `CAP_NET_RAW`.

::: tip TIP

It is possible to run Firedancer without running most of the stages of
`fdctl configure` if you are sure that your environment has been set up
correctly. 

:::

## ethtool
In addition to XDP, Firedancer uses recieve side scaling (RSS) to
improve network performance. This uses functionality of modern NICs to
steer packets to different queues to distribute processing among CPUs.
See the [kernel
documentation](https://docs.kernel.org/networking/scaling.html) for more
information.

In Firedancer, each `net` tile serves one network queue, so the
`ethtool` stage will modify the combined channel count of the configured
network device `[tiles.net.interface]` to be the same as the number of
`net` tiles, `[layout.net_tile_count]`. If your NIC does not support the
required number of queues, you will need to reduce the number of `net`
tiles, potentially down to one for NICs which don't support queues at
all.

The command run by the stage is similar to running `ethtool
--set-channels <device> combined <N>` but it also supports bonded
devices. We can check that it worked:

<<< @/snippets/ethtool.ansi

The stage only needs to be run once after boot but before running
Firedancer. It has no dependencies on any other stage, although it is
dependent on the number of  in your
configuration.

Changing device settings with `ethtool` requires root privileges, and
cannot be performed with capabilities.

## workspace
A Firedancer workspace is a special in-memory file with extension
`.wksp` created in the shmem mountpoints described above. It can be
thought of as just a chunk of memory. Almost all memory in Firedancer is
reserved, allocated, and initialized before running the program. The
allocations are made in this workspace, which has a special header so we
can look up where each one is.

In the future, Firedancer will support persistent workspaces that
are kept between runs. If that were supported, you could restart the
program very quickly from existing memory.

For now though, the stage must be run every time before running
Firedancer to get a cleanly initialized memory space.

The `workspace` stage only initializes memory that was already reserved
in a large block by the `shmem` stage, and does not require any
privileges. It needs to be run after the `shmem` stage but does not have
other dependencies.

The `check` mode will always fail, as the workspace always needs
to be reinitialized. The fini mode will remove existing workspaces from
the shared memory mount points.
