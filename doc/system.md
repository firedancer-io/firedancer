Preparing the system
====================

Prerequisites
-------------

This guide assumes the steps in [build.md](./build.md) have been completed.

Host setup
----------

The below describes running Firedancer optimized on a stock GCP
`n2-standard-80` instance with a stock GCP RHEL8.5 image.  For reference,
this instance is a dual socket 20 physical core Intel Cascade Lake at 2.8
GHz with hyperthreading enabled -> 2 NUMA nodes total, 80 logical cores
total).

Setup for other reasonably modern x86_64 architecture hosts (reasonable
modern here AVX2 support, this includes most Intel architectures since
~mid-2013 and AMD architectures since ~mid-2015) running reasonable
modern Linux-ish distributions is expected to be very similar.  Though
it is possible to run Firedancer to run on older hosts, it is not
supported and the below assumes a reasonably modern host.

While the Firedancer applications are meant to run from a normal user
account, tuning a host to run Firedancer optimally requires a some
administrative operations (should not be any more than the existing
validator).  Though it is possible to run Firedancer without any of
these tunings, it is not recommended and the below assumes the user has
the necessary `sudo` access.

- Configure the host for high performance by allowing users to lock
  pages in memory and increase the scheduler priority of performance
  critical user threads.  As superuser (e.g. `sudo su -`), add the
  following lines to `/etc/security/limits.conf`:
    ```
    * - memlock unlimited
    * - nice -20
    * - rtprio unlimited
    ```
  (The user might only opt to be more restrictiv if desired, e.g. only
  allow Firedancer users to do this.)  Recommend logging out and then
  logging back in again after making these changes.  `ulimit -a` can be
  used to tell if the new user limits have taken effect.  E.g., as a
  regular user, the following would indicate that the changes are in
  effect:

    ```
    $ ulimit -e -l -r
    scheduling priority             (-e) 40
    max locked memory       (kbytes, -l) unlimited
    real-time priority              (-r) unlimited
    ```

- Reserve host resources for application usage.  E.g.:
    ```
    $ sudo build/linux/gcc/x86_64/bin/fd_shmem_cfg \
      alloc 8 gigantic 0                           \
      alloc 8 gigantic 1                           \
      alloc 512 huge 0                             \
      alloc 512 huge 1
    ```
  will reserve
      8 1GiB pages on numa node 0,
      8 1GiB pages on numa node 1,
    512 2MiB pages on numa node 0, and
    512 2MiB pages on numa node 1
  on the host for application use (assuming the host in fact has enough
  free contiguous physical DRAM availability).  Adjust this as necessary
  for the number of cores, system DRAM availabiity, application mix,
  application configurations, etc.  `fd_shmem_cfg` has many powers.  Run
  `fd_shmem_cfg help` for more info.

- Create an appropriately permissioned sandbox for managing shared
  memory data structures.  E.g.:
    ```
    $ sudo build/linux/gcc/x86_64/bin/fd_shmem_cfg init 0700 [USER] ""
    ```
  where `[USER]` is the user that will run Firedancer applications.
  Multiple sandboxes with different permissions, users, groups can /
  coexist simultaneously (the `""` will be use default group of
  `[USER]`).

Next Steps
----------

At this point, your system is configured for the non-privileged operation
of Firedancer with optimized access to the host's CPUs and main memory.

Firedancer's applications can now be run, such as the demo explained in
[frankendancer.md](./frankendancer.md): a hybrid between the Solana Labs
and Firedancer validators.
