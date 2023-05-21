Building Firedancer
===================

The below describes building Firedancer from sources.

Prerequisites
-------------

Building Firedancer currently requires a relatively recent (~2019-ish)
GNU/Linux distribution and an x86_64 CPU.  Known compatible distros include
RHEL 8 and Ubuntu 22.04.  Non-GNU distributions such as Alpine Linux are
not yet well supported.

The below assumes a stock GCP `n2-standard-80` instance with a stock GCP
RHEL8.5 image. Minimal installs like those on stock cloud instances or
contains are missing even basic development tools. First log into the host
and configure user environment to taste (e.g. install favorite editors /
code development environment, etc).  This is not specific to Firedancer but
note hosts like this have very minimal installs on first login.

It is recommended to install standard development tools using the system
package manager. The exact steps depend on the Linux distribution of the
host.  These include such things as the stock `gcc` compiler, build tools
like `make`, version control systems like `git`, etc.  Firedancer likely
can use other tool chains / compilers (e.g. `clang`) but this is not
routinely tested currently.

- Debian, Ubuntu:
  ```
  $ sudo apt install build-essential
  ```
- Fedora, RHEL:
  ```
  $ sudo dnf groupinstall development
  ```
- Alpine:
  ```
  $ sudo apk add build-base
  ```

Downloading Firedancer sources
------------------------------

Get Firedancer using Git, e.g.:
```
$ git clone https://github.com/firedancer-io/firedancer.git firedancer
```
This will make a directory in the current directory called firedancer and
copy of the current head-of-tree code base into that directory. For the
rest of this guide, it is assumed that your current directory is
firedancer.
```
$ cd firedancer
```

Fetching Dependencies
---------------------

To simplify install and improve auditability, Firedancer tries to have
minimal external dependencies and then only use external dependencies that
are trivially installable on recent stock Linux distributions.

Current packages and tools used include:

| Name      | Version  | Environment | Purpose                                             |
|-----------|----------|-------------|-----------------------------------------------------|
| GNU make  | -        | Build       | Main build tool                                     |
| pkgconf   | -        | Build       | `pkg-config`, used to locate C library dependencies |
| quictls   | >=1.1.0  | Runtime     | OpenSSL fork, used for the QUIC protocol            |
| zlib      | -        | Runtime     | DEFLATE compression                                 |
| zstd      | -        | Runtime     | Zstandard compression                               |
| hwloc     | -        | Helper      | Helper utilities for NUMA                           |
| xdp-tools | >=1.2.6  | Helper      | Helper utilities for XDP programs                   |
| rocksdb   | >=7.10.2 | Compat      | Used to read Solana Labs validator blockstore DBs   |

### Using Nix

[Nix](https://nixos.org/) is a system automation tool. The provided
[`shell.nix`](./shell.nix) config sets up a shell environment containing
all build tools and dependencies using Nix.

```
$ nix-shell
```

Installing Nix requires root privileges, so this method is mainly suitable
existing users of Nix.

### Building from source

The [`deps.sh`](./deps.sh) bash script automates the setup of the build
environment. It will fetch third-party dependencies using Git and compile
them from source.

Building dependencies of Firedancer from source requires additional tools
such as Perl. `deps.sh` will prompt the user to fetch transitive build
dependencies using the system's package manager.

```
$ ./deps.sh help
$ ./deps.sh
```

Compiling using Make
--------------------

Build Firedancer. E.g. From the directory where firedancer was checked out:
```
make -j
```
This will do a parallel incremental build using all non-isolated cores and
should be reasonably quick even when done from scratch (less than a
minute).  The default machine target will be `MACHINE=linux_gcc_x86_64`
(details of this machine can be found in `config/linux_gcc_x86_64.mk`).
The build results will be in the relative directory
`build/linux/gcc/x86_64`.  `make` has many powers; run `make help` for more
info.  If building on a system with lots of isolated cores, see
`contrib/make-j`.

Next Steps
----------

If `make` prints no obvious errors or has nothing more to do, Firedancer
was successfully built.

The next guide describes system configuration in preparation of running
Firedancer: [system.md](./system.md)
