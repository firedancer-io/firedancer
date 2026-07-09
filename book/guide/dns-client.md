# DNS client

Firedancer includes a small embedded DNS client based on musl libc.
It resolves domain names (e.g. `entrypoint5.devnet.solana.com`) to IP
addresses.

Firedancer does not use system libraries (glibc) for DNS resolution
and thus behaves differently from other programs on a typical system.

## Important

For sane deploys, no difference should be visible (e.g. default Ubuntu
or Fedora config in a datacenter).

The following behavior could cause issues:
- containerized deploys
- GNU name service switch (NSS) custom config
- removing and recreating `/etc/resolv.conf` or `/etc/hosts` while
  Firedancer is running (rewriting it in-place is fine)

## Users

The following Firedancer components issue DNS queries:

- **startup**: resolve snapshot servers in `[snapshots.sources.servers]`
- **bundle**: when connecting to the bundle server
- **event**: when connecting to the event telemetry server

The above components are all optional. Firedancer does not require DNS
to operate, and is designed to survive a total DNS outage.

## Local resolver

Most modern Linux systems locally run `systemd-resolved`.
Firedancer works best with such a local resolver.

`systemd-resolved` is a lightweight stub resolver that improves DNS
client security by using encrypted DNS connections and DNSSEC if
available.

## Motivation

Using Linux system libraries for DNS resolution is at odds with
Firedancer's strict sandbox. Sending a DNS query using glibc's
`getaddrinfo` library call opens pandora's box: it dynamically loads and
executes new program code, spawns new threads, opens new files, maps
arbitrary new memory into all threads.

It is impossible to know what a system DNS resolver will
exactly do because it depends on system config (`/etc/nsswitch.conf`).

Therefore, system resolvers are fundamentally incompatible with
proper sandboxing. It is not acceptable to weaken the sandbox for DNS
resolution when we could just use a better DNS library, at the minimal
cost of breaking support for obscure DNS features.

The included DNS library was designed to be predictable and sandbox
friendly:
- about ~1000 lines of code from musl libc, vendored with Firedancer
  source code
- does not spawn threads
- does not request memory (no heap allocations)
- opens only two files (at startup)

## Behavior

Internally, the Firedancer DNS resolver works roughly as follows.

On startup:
- open `/etc/hosts` (hardcoded path)
- open `/etc/resolv.conf` (hardcoded path)

Each time a domain name is queried:
- re-read `/etc/hosts`, check for a match
- re-read `/etc/resolv.conf`, to find which name servers might have an
  answer
- create UDP and TCP sockets (multiple if there is more than one
  resolver)
- until an A, AAAA, NXDOMAIN, or SERVFAIL is found
  - fire DNS requests
  - block until there is a response
  - repeat for CNAMEs
