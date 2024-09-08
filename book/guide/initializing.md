# Initializing

## Overview
The `fdctl configure` command is used to setup the host operator system
so Firedancer can run correctly. It does three things:

* **hugetlbfs** Reserves huge and gigantic pages for use by Firedancer.
* **sysctl** Sets required kernel parameters.
* **ethtool-channels** Configures the number of channels on the network
device.
* **ethtool-gro** Disable generic-receive-offload (GRO) on the network
device.

The `hugetlbfs` configuration must be performed every time the system
is rebooted, to remount the `hugetlbfs` filesystems, but `sysctl`,
`ethtool-channels` and `ethtool-gro` configuration only needs to be
performed on the machine once.

The configure command is run like `fdctl configure <mode> <stage>...`
where `mode` is one of:

 - `init` Configures the provided stages if they are not already
   configured.
 - `check` Check if each stage is already configured. The command will
   exit with an error code if they are not. `check` never requires
   privileges and will not make any changes to the system.
 - `fini` Unconfigure (reverse) the stage if it is reversible.

`stage` can be one or more of `hugetlbfs`, `sysctl`, `ethtool-channels`
or `ethtool-gro` and these stages are described below. You can also use
the stage `all` which will configure everything.

Stages have different privilege requirements, which you can see by
trying to run the stage without privileges. The `check` mode never
requires privileges, and the `init` mode will only require
privileges if it needs to actually change something.

## hugetlbfs
The `hugetlbfs` stage is used to reserve `huge` (2MiB) and `gigantic`
(1GiB) memory pages from the Linux kernel for use by Firedancer. See
also the [kernel
documentation](https://docs.kernel.org/admin-guide/mm/hugetlbpage.html)
of these pages. Almost all memory in Firedancer is allocated out of
these pages for performance reasons.

This is a two step process. First, the number of `huge` and `gigantic`
pages available on the entire system is increased in the kernel by
increasing `/sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages`
until the `free_hugepages` value is high enough for all the memory
needs of the validator.

Once the pages have been reserved globally in the kernel pool, they are
assigned specifically to Firedancer by creating a `hugetlbfs` mount at
each of `/mnt/.fd/.gigantic/` and `/mnt/.fd/.huge` for gigantic and huge
pages respectively. These paths can be configured in the TOML file under
the `[hugetlbfs]` section. Lets run it:

<<< @/snippets/hugetlbfs.ansi

This stage requires root privileges, and cannot be performed with
capabilities. If the required hugetlbfs mounts are already present, with
at least the amount of memory reserved that we required then the `init`
mode does nothing and the `check` mode will return successfully
without requiring privileges.

The `fini` mode will unmount the two filesystems, and remove them from
`/mnt/.fd/`, although it will leave the `/mnt/.fd/` directory in place.
The `fini` mode will not succeed if memory from the mounts is mapped
into a running process.

If fini succeeds, the huge and gigantic pages that Firedancer had
reserved will be returned to the kernel global pool so they can be used
by other programs, but the global pool size will not be decreased, even
if it was earlier increased during `init`.

::: tip TIP

The `hugetlbfs` step should be run immediately when the system is booted.
If run later, it may fail because the operating system memory is
fragmented and a large contiguous block cannot be reserved.

:::

## sysctl
It is suggested to run Firedancer with certain kernel parameters tuned
for best performance. The `sysctl` stage will check and configure these
parameters. The stage will only increase values to meet the minimum, and
will not decrease them if the minimum is already met.

| Sysctl                                  | Minimum     | Required | Description
|-----------------------------------------| ----------- | -------- | -----------
| /proc/sys/vm/max_map_count              | 1000000     | Yes      | Agave accounts database requires mapping many files.
| /proc/sys/fs/file-max                   | 1024000     | Yes      | Agave accounts database requires opening many files.
| /proc/sys/fs/nr_open                    | 1024000     | Yes      | Agave accounts database requires opening many files.
| /proc/sys/net/ipv4/conf/lo/rp_filter    | 2           | Yes      | If sending QUIC transactions to Firedancer over loopback, this must be enabled to receive a response. Otherwise Linux will drop response packets due to limitations in the kernel eBPF networking stack. The sendTransaction RPC call will send over loopback. 
| /proc/sys/net/ipv4/conf/lo/accept_local | 1           | Yes      | If sending QUIC transactions to Firedancer over loopback, this must be enabled to receive a response. Otherwise Linux will drop response packets due to limitations in the kernel eBPF networking stack. The sendTransaction RPC call will send over loopback.
| /proc/sys/net/core/bpf_jit_enable       | 1           | No       | Firedancer uses BPF for kernel bypass networking. BPF JIT makes this faster.
| /proc/sys/kernel/numa_balancing         | 0           | No       | Firedancer assigns all memory to the right NUMA node, and rebalancing will make the system slower.

Sysctls that are not required will produce a warning if they are not set
correctly, but configuration will proceed and exit normally.

The `init` mode requires either `root` privileges, or to be run with
`CAP_SYS_ADMIN`. The `fini` mode does nothing and kernel parameters
will never be reduced or changed back as a result of running
`configure`.

## ethtool-channels
In addition to XDP, Firedancer uses receive side scaling (RSS) to
improve network performance. This uses functionality of modern NICs to
steer packets to different queues to distribute processing among CPUs.
See the [kernel
documentation](https://docs.kernel.org/networking/scaling.html) for more
information.

In Firedancer, each `net` tile serves one network queue, so the
`ethtool-channels` stage will modify the combined channel count of the
configured network device `[tiles.net.interface]` to be the same as the
number of `net` tiles, `[layout.net_tile_count]`. If your NIC does not
support the required number of queues, you will need to reduce the
number of `net` tiles, potentially down to one for NICs which don't
support queues at all.

The command run by the stage is similar to running `ethtool
--set-channels <device> combined <N>` but it also supports bonded
devices. We can check that it worked:

<<< @/snippets/ethtool-channels.ansi

The stage only needs to be run once after boot but before running
Firedancer. It has no dependencies on any other stage, although it is
dependent on the number of `net` tiles in your configuration.

Changing device settings with `ethtool-channels` requires root privileges, and
cannot be performed with capabilities.

## ethtool-gro
XDP is incomatible with a feature of network devices called
`generic-receive-offload`. If enabled, this feature must be disabled for
Firedancer to work.

The command run by the stage is similar to running `ethtool --offload
generic-receive-offload <device> off` but it also supports bonded
devices. We can check that it worked:

<<< @/snippets/ethtool-gro.ansi

The stage only needs to be run once after boot but before running
Firedancer. It has no dependencies on any other stage.

Changing device settings with `ethtool-gro` requires root privileges, and
cannot be performed with capabilities.
