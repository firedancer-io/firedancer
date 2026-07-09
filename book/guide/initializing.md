# Initializing

## Overview
The `fdctl configure` command is used to setup the host operator system
so Firedancer can run correctly. It does the following:

* **hugetlbfs** Reserves huge and gigantic pages for use by Firedancer.
* **sysctl** Sets required kernel parameters.
* **hyperthreads** Checks hyperthreaded pair for critical CPU cores.
* **bonding** Prepares bonded network devices for XDP networking.
* **ethtool-channels** Configures the number of channels on the network
device.
* **ethtool-offloads** Modify offload feature flags on the network device.
* **ethtool-loopback** Disable tx-udp-segmentation on the loopback
device.
* **irq-affinity** Prevents the kernel from routing IRQs to CPU cores
  used by Firedancer (via `/proc/irq`).
* **irq-balance** Prevents the irqbalance daemon from routing IRQs to
  CPU cores used by Firedancer (via `/run/irqbalance`).
* **kworkers** Prevents unbound kernel workqueue workers from running
  on CPU cores used by Firedancer (via
  `/sys/devices/virtual/workqueue/cpumask`).
* **cpuset** Creates an isolated cgroup cpuset partition over the CPU
  cores used by Firedancer, so no other process can be scheduled onto
  them (via `/sys/fs/cgroup`).

The `hugetlbfs` configuration must be performed every time the system
is rebooted, to remount the `hugetlbfs` filesystems, as do `sysctl`,
`ethtool-channels` and `ethtool-offloads` to reconfigure the networking
device, `irq-affinity` and `irq-balance` configure IRQ affinities for
CPUs.

The configure command is run like `fdctl configure <mode> <stage>...`
where `mode` is one of:

 - `init` Configures the provided stages if they are not already
   configured.
 - `check` Check if each stage is already configured. The command will
   exit with an error code if they are not. `check` never requires
   privileges and will not make any changes to the system.
 - `fini` Unconfigure (reverse) the stage if it is reversible.

`stage` can be one or more of `hugetlbfs`, `sysctl`, `hyperthreads`,
`bonding`,  `ethtool-channels`, `ethtool-offloads`, `ethtool-loopback`,
`irq-affinity`, `irq-balance`, `kworkers`, `cpuset`, and `snapshots`
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

This stage looks to see if the CPU is hyperthreaded, and will print a
warning for the operator if the pair of these tiles are used or online.

A typical warning on a hyperthreaded system with `auto` layout looks
like this:

<<< @/snippets/hyperthreads.ansi

When using the `auto` layout, Firedancer will ensure no other tiles are
assigned to run on the hyperthread pairs, but if using a manual layout,
it is possible to assign another tile to the pair.

This stage has no dependencies on any other stage, but it is dependent
on the topology specified in your configuration. It is recommended that
you turn off the CPUs specified in the warning for optimal performance.

## bonding
Validator hosts commonly use bonded network devices to increase
bandwidth and fault tolerance.  Common Linux distributions pick defaults
for bonding driver configuration that are incompatible with the XDP mode
of some network drivers.  When attaching XDP to a network device part of
such an incorrectly configured bond, the bonding driver may erroneously
consider that device as failed, leading to connectivity loss.

Firedancer reconfigures bonding driver parameters to tolerate brief
downtime when configuring XDP networking.  This is done by increasing
the `miimode`, `downdelay`, and `peer_notif_delay` timeout parameters in
`/sys/class/net/bond0/bonding/` to five seconds.

<<< @/snippets/bonding.ansi

Changing device settings with `bonding` requires root privileges, and
cannot be performed with capabilities.

## ethtool-channels
In addition to XDP, Firedancer uses receive side scaling (RSS) to
improve network performance. This uses functionality of modern NICs to
steer packets to different queues to distribute processing among CPUs.
See the [kernel
documentation](https://docs.kernel.org/networking/scaling.html) for more
information.

In Firedancer, each `net` tile serves just one network queue, so the
`ethtool-channels` stage will modify the network device `[net.interface]`
configuration such that all packets needed by Firedancer are steered to
the proper queue(s).  There are three modes, selectable in your
configuration, that govern this behavior:

 * **simple** mode modifies the combined channel count of the configured
network device to be the same as the number of `net` tiles,
`[layout.net_tile_count]`. If your NIC does not support the required
number of queues, you will need to reduce the number of `net` tiles,
potentially down to one for NICs which don't support queues at all.  This
is the default mode and should work for all network devices.  Because
the queue count is reduced system-wide, not solely for Firedancer, this
can have a negative performance impact on non-Firedancer network traffic.

 * **dedicated** mode reserves a dedicated hardware queue for each `net`
tile.  This is the more advanced mode and may not work with all network
devices.  By modifying the RXFH indirection table and installing ntuple
rules, Firedancer traffic is directed onto the dedicated queues and all
other traffic is sharded amongst the rest.  This has a performance
benefit for both Firedancer and non-Firedancer traffic.

 * **auto** mode attempts to initialize the device in dedicated mode
and automatically falls back to simple mode if any failure occurs.

The command run by the stage in simple mode is similar to running
`ethtool --set-channels <device> combined <N>` but it also supports
bonded devices. We can check that it worked:

<<< @/snippets/ethtool-channels.ansi

The stage only needs to be run once after boot but before running
Firedancer. It has no dependencies on any other stage, although it is
dependent on the number of `net` tiles in your configuration.

Changing device settings with `ethtool-channels` requires root
privileges, and cannot be performed with capabilities.

## ethtool-offloads
XDP is incompatible with a feature of network devices called
`rx-udp-gro-forwarding`. This feature must be disabled for Firedancer
to work. GRE segmentation offload is also disabled.

The command run by the stage is similar to running
`ethtool --features <device> <feature> off` but it also supports bonded
devices. We can check that it worked:

<<< @/snippets/ethtool-offloads.ansi

The stage only needs to be run once after boot but before running
Firedancer. It has no dependencies on any other stage.

Changing device settings with `ethtool-offloads` requires root
privileges, and cannot be performed with capabilities.

## ethtool-loopback
XDP is incompatible with localhost UDP traffic using a feature called
`tx-udp-segmentation`. This feature must be disabled when connecting Agave
clients to Firedancer over loopback, or when using Frankendancer.

The command run by the stage is `ethtool --features lo tx-udp-segmentation
off`. We can check that it worked:

<<< @/snippets/ethtool-loopback.ansi

The stage only needs to be run once after boot but before running
Firedancer. It has no dependencies on any other stage.

Changing device settings with `ethtool-loopback` requires root privileges,
and cannot be performed with capabilities.

## irq-affinity
By default, Linux dispatches device interrupts (IRQs) to arbitrary
CPUs. Since socket based networking relies heavily on IRQs, heavy
incoming traffic can starve a Firedancer tile of CPU time. Tiles
cannot move out of the way, since they are pinned to one CPU each.

The `irq-affinity` stage rewrites the affinity mask of every device
interrupt in `/proc/irq/<N>/smp_affinity` to exclude the CPU cores
used by Firedancer tiles, so interrupts are delivered to the
remaining housekeeping CPUs instead.

Some interrupts cannot be moved: the kernel manages the affinity of
certain interrupts itself (for example NVMe queue interrupts) and
rejects updates to them. There is no way to ask the kernel which
interrupts are movable, so the stage attempts to reconfigure each one
and skips those that are rejected. Such managed interrupts rarely
fire on tile CPUs in practice, because they only handle I/O submitted
from the CPUs they are bound to, and tiles submit little I/O. The
per-tile interrupt counts in the monitoring output show any residual
interrupt activity on tile CPUs.

<<< @/snippets/irq-affinity.ansi

The `init` mode requires root privileges. The `fini` mode re-admits
tile CPUs into the interrupt affinity masks. Note the kernel does not
move an already-placed interrupt when its mask is widened, so `fini`
restores the masks but not necessarily the previous interrupt
placement.

If the `irqbalance` daemon is running (see below), it will fight this
stage by periodically rewriting the affinity masks, so the
`irq-balance` stage should be configured as well.

## irq-balance
The `irqbalance` daemon is a userspace service, enabled by default on
many distributions, which periodically rewrites all interrupt
affinity masks to spread interrupt load across CPUs, reacting to
system load and thermal events. Left alone it will undo the work of
the `irq-affinity` stage and route interrupts back onto Firedancer
tile CPUs.

The `irq-balance` stage connects to the daemon's control socket at
`/run/irqbalance/` and instructs it to ban the tile CPUs from
interrupt placement.

<<< @/snippets/irq-balance.ansi

This configuration is ephemeral: irqbalance forgets socket-applied
settings when it restarts, so the stage must be re-run if the daemon
restarts. For a permanent setting, place the banned CPU list in the
irqbalance configuration file (`IRQBALANCE_BANNED_CPULIST` in
`/etc/sysconfig/irqbalance` or `/etc/default/irqbalance`), or disable
the daemon entirely on dedicated validator hosts.

The stage does nothing if irqbalance is not running. The `init` mode
requires root privileges.

## kworkers
The Linux kernel defers certain work (dirty page writeback, filesystem
maintenance, various driver bottom halves) to worker threads called
kworkers. Workers servicing "unbound" workqueues may be scheduled onto
any CPU allowed by a global mask, which by default includes all CPUs.
A burst of deferred kernel work can therefore preempt a Firedancer tile
for milliseconds at a time.

The `kworkers` stage removes tile CPUs from the unbound workqueue mask
at `/sys/devices/virtual/workqueue/cpumask`, so deferred kernel work
runs on the remaining housekeeping CPUs instead.

Per-CPU (bound) kworkers are unaffected: they only run work generated
on their own CPU, which the `irq-affinity` and `cpuset` stages
minimize. Note that changing the mask only affects newly queued work,
so the system converges after `init` rather than becoming instantly
silent.

<<< @/snippets/kworkers.ansi

The `init` mode requires root privileges. The `fini` mode restores the
mask to all host CPUs, which is the kernel default (if the operator
had customized the mask before `init`, that customization is not
restored). The stage is skipped on kernels that do not expose the
workqueue mask.

## cpuset
The `cpuset` stage creates a cgroup v2 cpuset partition in "isolated"
mode over the Firedancer tile CPUs, at `/sys/fs/cgroup/<name>` where
`<name>` is the instance [name] from the configuration. An isolated
partition removes its CPUs from the kernel scheduler's load balancing
domains entirely: no other process on the system can be scheduled
onto, or even set affinity to, the isolated CPUs. It is the strongest
available protection against other software stealing CPU time from
the validator, and is the runtime-configurable equivalent of the
`isolcpus=` kernel boot parameter (which the kernel has deprecated in
favor of this mechanism).

In addition to the tile CPUs, the partition includes the unused
hyperthread siblings of the performance-sensitive `pack` and `poh`
tiles (see the `hyperthreads` stage). An isolated, unused sibling
stays permanently idle in a deep sleep state, which relinquishes the
physical core's shared resources comparably to taking the CPU offline.
With the partition in place, the `hyperthreads` stage warnings about
online siblings are suppressed.

<<< @/snippets/cpuset.ansi

When Firedancer starts, the tile launcher automatically joins tile
processes into the cgroup before pinning them to their CPUs; no
further operator action is needed. Note this means that once the
partition exists, only Firedancer versions that are aware of it can
pin tiles to those CPUs — if you observe `sched_setaffinity` EINVAL
failures from other tooling, remove the partition with `fini`.

The stage requires cgroup v2 (the unified hierarchy, standard on
modern distributions) with the cpuset controller, and a kernel
supporting isolated partitions (5.15 or later). It is skipped when
cgroup v2 is unavailable. If the cgroup exists but covers the wrong
CPUs (for example after changing `[layout.affinity]`), starting
Firedancer fails with instructions to re-run `init`.

The `init` mode requires root privileges. The `fini` mode downgrades
the partition and removes the cgroup, returning the CPUs to the
system.

::: tip NOTE

The `kworkers` and `cpuset` stages are optional hardening: Firedancer
runs correctly without them, and they are recommended for production
validator deployments to reduce scheduling jitter on tile CPUs.

When starting Firedancer, two additional read-only checks run
alongside these stages: `nohz-full` and `rcu-nocbs`. These verify the
kernel `nohz_full=` and `rcu_nocbs=` boot parameters cover the tile
CPUs, which eliminates periodic timer tick interrupts and RCU callback
processing on those cores. Since boot parameters cannot be changed at
runtime, these checks only print a suggested kernel command line and
never fail.
They can also be run manually with `configure check nohz-full
rcu-nocbs`.

:::

## snapshots
When starting up, validators must load a snapshot to catch up to the
current state of the blockchain. Snapshots are downloaded from other
validator peers in the cluster and are stored to a snapshots directory.

In init, the snapshots configure phase will create the snapshots
directory if it does not exist. In fini, the snapshots configure phase
will remove the snapshots directory recursively.

::: tip NOTE

The snapshots configure phase is only enabled in the Firedancer binary.
