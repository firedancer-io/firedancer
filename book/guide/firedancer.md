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

## Firedancer’s goal of improving Solana:
Firedancer is intended to replicate Solana’s functionality but with
higher performance. Consistent with Solana’s vision, the goal is to
eliminate software inefficiencies and drive the performance to the
limits of the hardware, while attempting to not create any new
vulnerabilities. Firedancer makes minimal use of third party libraries
for cryptographic and network functionality where there are currently
bottlenecks.

As a second validator codebase, Firedancer removes the risk of a single
point of failure. As nodes are distributed more evenly among several
independent codebases, the overall network will become more robust
against any one bug. Additionally, Firedancer is written in C, in
contrast to the Rust codebase of the original Solana validator, which
further reduces the likelihood of a vulnerability affecting the entire
network.

Firedancer’s security model is inspired by methods used in the browser
world which is under perpetual attack. Diversification of security
approaches is another way the second validator intends to make the
network more robust.

Improved performance also means current performance needs can be
achieved with lower cost hardware. This should encourage additional
validator operators to join the network who were otherwise prohibited by
current hardware requirements.

## Firedancer
Firedancer is a fully independent Solana validator. Networking, block
production, the runtime, and consensus are all implemented in
Firedancer's own codebase, and it does not run Agave alongside it.

Firedancer is released as tagged versions in the `vYY.MM.PATCH` format.
A new release line starts every month with new features and performance
improvements, and patch releases carry occasional fixes for active
release lines. Operators should run a tagged release rather than `main`.
See [Releases](./getting-started.md#releases) for details.

Frankendancer is no longer supported.

## This Book
This book is intended for operators and administrators already familiar
with running an Agave validator, as Firedancer heavily leans on the
same concepts and components. To get up to speed there, read the Solana
Labs [validators guide](https://docs.solana.com/running-validator).

The guide describes how to start and run a healthy Firedancer validator
node. The validator is under heavy development and should be considered
beta software, thank you for being on the bleeding edge.

## Help
Firedancer is beta software and you should expect hiccups when getting
started with, and when operating the validator. The Firedancer
development team can help diagnose any issues. The main place to discuss
Firedancer operational issues is the `#firedancer-operators` channel in
the [Solana Tech discord](https://discord.com/invite/solana).

## Contributing
Firedancer is open source and being developed on GitHub. All
contributions are welcome. Jump is currently the primary contributor as
the project is in the initial development phase, but Firedancer is a
decentralized, community validator and project stewardship will be
transitioned to the community as the project matures.

## License
Firedancer is available under the [Apache-2.0
license](https://www.apache.org/licenses/LICENSE-2.0). Firedancer also
includes external libraries that are available under a variety of
licenses. See
[LICENSE](https://github.com/firedancer-io/firedancer/blob/main/LICENSE)
for the full license text and
[NOTICES](https://github.com/firedancer-io/firedancer/blob/main/NOTICE)
for additional details on external libraries.
