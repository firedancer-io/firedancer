Getting started
===============

Host setup
----------

The below describes building Firedancer from scratch and running it
optimized on a stock GCP `n2-standard-80` instance with a stock GCP
RHEL8.5 image.  For reference, this instance is a dual socket 20
physical core Intel Cascade Lake at 2.8 GHz with hyperthreading enabled
-> 2 NUMA nodes total, 80 logical cores total).

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

- Log into the host and configure user environment to taste (e.g.
  install favorite editors / code development environment, etc).  This
  is not specific to Firedancer but note hosts like this have very
  minimal installs on first login.

- Install standard development tools.
    ```
    $ sudo dnf groupinstall development
    ```
  As mentioned above, the minimal installs are missing even basic
  development tools.  The `development` group includes such things as
  the stock `gcc` compiler, build tools like `make`, version control
  systems like `git`, etc.  Firedancer likely can use other tool chains
  / compilers (e.g. `clang`) but this is not routinely tested currently.

- Install additional dependencies.
    ```
    $ sudo dnf install numactl-devel hwloc
    ```
  To simplify install and Firedancer tries to have virtually no external
  dependencies that aren't readily nearly universally prepackaged
  available in stock Linux distributions.  `numactl-devel` and `hwloc`
  are not included in `development` by default above unfortunately but
  they are widely available pre-packaged.  They provide APIs used to
  help implement various NUMA optimizations on the host.

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
    $ ulimit -a
    ... snip ...
    scheduling priority             (-e) 40
    ... snip ...
    max locked memory       (kbytes, -l) unlimited
    ... snip ...
    real-time priority              (-r) unlimited
    ... snip ...
    ```

- Get Firedancer.  E.g.:
    ```
    $ git clone https://github.com/firedancer-io/firedancer.git firedancer
    ```
  will make a directory in the current directory called firedancer and
  copy of the current head-of-tree code base into that directory.

- Build Firedancer. E.g. From the directory where firedancer was 
  checked out:
    ```
    make -j
    ```
  This will do a parallel incremental build using all non-isolated cores
  and should be reasonably quick even when done from scratch (less than
  a minute).  The default machine target will be `MACHINE=rh8_x86_64`
  (details of this machine can be found in `config/rh8_x86_64.mk`).  The
  build results will be in the relative directory `build/rh8/x86_64`.
  `make` has many powers; run `make help` for more info.  If building on
  a system with lots of isolated cores, see `contrib/make-j`.

- Reserve host resources for application usage.  E.g.:
    ```
    $ sudo build/rh8/x86_64/bin/fd_shmem_cfg \
      alloc 8 gigantic 0                     \
      alloc 8 gigantic 1                     \
      alloc 512 huge 0                       \
      alloc 512 huge 1
    ```
  will reserve
      8 2GiB pages on numa node 0,
      8 2GiB pages on numa node 1,
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
    $ sudo build/rh8/x86_64/bin/fd_shmem_cfg init 0700 [USER] ""
    ```
  where `[USER]` is the user that will run Firedancer applications.
  Multiple sandboxes with different permissions, users, groups can /
  coexist simultaneously (the `""` will be use default group of
  `[USER]`).

Running
-------

TODO

