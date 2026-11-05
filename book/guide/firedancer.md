# Firedancer
## Why is Jump Trading Group creating Firedancer?
There are many blockchains in existence today, each with different
advantages and disadvantages. What differentiates Solana is its design
which enables the dissemination of frequent, inexpensive information. It
is cheap to use so it does not impose an onerous cost on the end user.
Solana can handle the high throughput requirements that come with the
bursts of activity.

Over the past twenty years, Jump has built a high-capacity,
high-reliability, low-latency global network to support our trading and
address many of the scaling problems that Solana is currently facing. In
doing so, we have had to think hard about how to take a flood of market
data and process it more efficiently than our competitors, which means
pushing the limits of our hardware.

Leveraging our experience over the last two decades in building this
global network, we believe we are well-positioned to significantly
improve the power, reliability, and security of the Solana ecosystem.

The Firedancer project requires a significant commitment of Jump
developer resources, and we are appreciative of the support from the
Solana Foundation to make this project possible.

## How Firedancer improves Solana
Firedancer is a fully independent Solana validator. Networking, block
production, the runtime, and consensus are all implemented in
Firedancer's own codebase, distinct from Agave. Consistent with Solana's
vision, it eliminates software inefficiencies and drives performance to
the limits of the hardware, without introducing new vulnerabilities.
Firedancer makes minimal use of third party libraries for cryptographic
and network functionality where there are currently bottlenecks.

As a second validator codebase, Firedancer removes the risk of a single
point of failure. As nodes are distributed more evenly among several
independent codebases, the overall network becomes more robust
against any one bug. Extending that independence, Firedancer is written
in C, in contrast to the Rust codebase of the original Solana validator,
which further reduces the likelihood of a vulnerability affecting the
entire network.

In Firedancer's security model, each tile runs as a separate process in
a highly restrictive sandbox, using seccomp, user namespaces, and
dropped capabilities, with access to only the few system calls and
memory regions it needs. Private keys are isolated in a dedicated
signing tile, out of reach of network-facing processes.

Higher performance lets the network handle far more activity on the
same hardware, and lets operators keep up with today's load on cheaper
machines, lowering the barrier for new validators to join.

## Releases
Firedancer is released as
[tagged versions](https://github.com/firedancer-io/firedancer/releases)
in the `vYY.MM.PATCH` format. A new release line starts every month with
new features and performance improvements, and patch releases carry
minor fixes for active release lines.

Frankendancer releases are no longer supported.

## This Book
This book is for operators and administrators running a Firedancer
validator, and covers installing, configuring, and operating it. It
assumes some familiarity with running a Solana validator. If you are new
to that, start with the
[validators guide](https://docs.solana.com/running-validator).

## Help
For help setting up or operating Firedancer, ask in the
`#firedancer-operators` channel in the
[Solana Tech discord](https://discord.com/invite/solana),
where the Firedancer development team can help diagnose issues.

## Contributing
Firedancer is open source and being developed on GitHub. Jump is the
primary contributor through the project's production and active
development, but Firedancer is open to public contribution.

## License
Firedancer is available under the [Apache-2.0
license](https://www.apache.org/licenses/LICENSE-2.0). Firedancer also
includes external libraries that are available under a variety of
licenses. See
[LICENSE](https://github.com/firedancer-io/firedancer/blob/main/LICENSE)
for the full license text and
[NOTICES](https://github.com/firedancer-io/firedancer/blob/main/NOTICE)
for additional details on external libraries.
