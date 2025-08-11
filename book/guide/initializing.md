# Initializing

## Overview
The `fdctl configure` command is used to setup the host operator system
so Firedancer can run correctly. It does the following:

* **hugetlbfs** Reserves huge and gigantic pages for use by Firedancer.
* **sysctl** Sets required kernel parameters.
* **hyperthreads** Disables hyperthreaded pair for critical CPU cores.
* **ethtool-channels** Configures the number of channels on the network
device.
* **ethtool-gro** Disable generic-receive-offload (GRO) on the network
device.

The `hugetlbfs` configuration must be performed every time the system
is rebooted, to remount the `hugetlbfs` filesystems, as do `sysctl`,
`ethtool-channels` and `ethtool-gro` to reconfigure the networking
device, and `hyperthreads` to configure CPU cores.

The configure command is run like `fdctl configure <mode> <stage>...`
where `mode` is one of:

 - `init` Configures the provided stages if they are not already
   configured.
 - `check` Check if each stage is already configured. The command will
   exit with an error code if they are not. `check` never requires
   privileges and will not make any changes to the system.
 - `fini` Unconfigure (reverse) the stage if it is reversible.

`stage` can be one or more of `hugetlbfs`, `sysctl`, `hyperthreads`,
`ethtool-channels`, `ethtool-gro`, and `snapshots`
and these stages are described below. You can also use the stage `all`
which will configure everything.

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

## hyperthreads
Most work in Firedancer can be scaled with the number of CPU cores, but
there are two jobs (tiles) which must run serially on a single core:

 * **pack** Responsible for scheduling transactions for execution when
we are leader.
 * **poh** Performs repeated `sha256` hashes, and periodically stamps
these hashes into in-progress blocks when we are leader.

Because any interruption, context switch, or sharing of the CPU core
that these jobs run on could cause skipped leader slots or unfull
blocks, Firedancer expects them to get a dedicated core. This means on
machines with a hyperthreaded CPU, the hyperthreaded pair of these tiles
should be switched to offline.

This stage looks to see if the CPU is hyperthreaded, and will switch the
pair of these tiles to `offline`. All other CPU cores, if `offline` will
be switched back to `online`.

The specific command run by the stage is toggling values in
`/sys/devices/system/cpu/cpu<id>/online` between `0` and `1`. We can run
the command with a typical auto layout to see:

<<< @/snippets/hyperthreads.ansi

When using the `auto` layout, Firedancer will ensure no other tiles are
assigned to run on the hyperthread pairs, but if using a manual layout,
it is possible to assign another tile to the pair, in which case
configuration will succeed without turning the pair off.

The stage only needs to be run once after boot but before running
Firedancer. It has no dependencies on any other stage, although it is
dependent on the topology specified in your configuration.

Changing CPUs to offline or online requires root privileges, and cannot
be performed with capabilities.

The `fini` mode will switch all CPUs back to online.

## ethtool-channels
In addition to XDP, Firedancer uses receive side scaling (RSS) to
improve network performance. This uses functionality of modern NICs to
steer packets to different queues to distribute processing among CPUs.
See the [kernel
documentation](https://docs.kernel.org/networking/scaling.html) for more
information.

In Firedancer, each `net` tile serves one network queue, so the
`ethtool-channels` stage will modify the combined channel count of the
configured network device `[net.interface]` to be the same as the number
of `net` tiles, `[layout.net_tile_count]`. If your NIC does not support
the required number of queues, you will need to reduce the number of
`net` tiles, potentially down to one for NICs which don't support queues
at all.

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
XDP is incompatible with a feature of network devices called
`generic-receive-offload`. This feature must be disabled for Firedancer
to work.

The command run by the stage is similar to running `ethtool --offload <device> generic-receive-offload off`
but it also supports bonded devices. We can check that it worked:

<<< @/snippets/ethtool-gro.ansi

The stage only needs to be run once after boot but before running
Firedancer. It has no dependencies on any other stage.

Changing device settings with `ethtool-gro` requires root privileges, and
cannot be performed with capabilities.

## snapshots
When starting up, validators must load a snapshot to catch up to the
current state of the blockchain. Snapshots are downloaded from other
validator peers in the cluster and are stored to a snapshots directory.

In init, the snapshots configure phase will create the snapshots
directory if it does not exist. In fini, the snapshots configure phase
will remove the snapshots directory recursively.

::: tip NOTE

The snapshots configure phase is only enabled in the Firedancer binary.
