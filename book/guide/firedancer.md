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

## What does the Firedancer team aim to deliver?
At a high level, the three functional blocks of Solana are network,
runtime, and the consensus mechanism.

The network layer is essentially code complete, and is being tuned and
undergoing reviews by auditors.

The first Firedancer validator to go into testnet [is version 0.1 and]
is nicknamed Frankendancer. It is Firedancer’s networking layer grafted
onto the Solana runtime and consensus code. Although the networking
layer will be much faster, it is likely that the performance of the
Frankendancer validator will be bottlenecked by the legacy runtime and
consensus code. Frankendancer still offers an advantage with DoS
mitigation.

This document explains how to bring up Frankendancer in testnet. We hope
to get feedback from validators while we go through security audits and
continue to refine the codebase. The goal is to get Frankendancer to
mainnet in Q2 2024.

In parallel the team has been working on replicating the functionality
of the runtime and consensus code, with the goal of delivering a fully
independent validator by the end of 2024.

## Frankendancer
Firedancer is a new Solana validator with a new codebase, but it is
being developed incrementally. To enable testing and deployment before
the entire Solana protocol has been implemented we rely on the existing
Solana Labs validator code to provide functionality that is missing.
This side-by-side configuration is referred to as "frankendancer".

Currently, Firedancer has implemented the following parts:

 * The QUIC and UDP ingress networking pieces, using high performance
   kernel bypass networking.

 * The block distribution engine and egress networking, also using
   kernel bypass. The engine contains a full reimplementation of erasure
   coding and the Solana turbine protocol for packet routing.

 * Signature verification with a custom AVX512 ED25519 implementation.

 * The block packing logic.

All other functionality is retained by Solana Labs, including the
runtime itself which tracks account state and executes transactions.

This means building and running a Firedancer validator also builds a
Solana Labs validator and runs it as a child process. The Solana Labs
process is fully built into and managed by Firedancer and you do not
need to start it up or otherwise configure it.

Because of this side by side operation, existing knowledge and processes
you have from running a Solana Labs validator will likely apply to
Firedancer too. For example, the monitoring and metrics are left the
same, and you will run the same Solana Labs `solana` CLI command.

## This Book
This book is intended for operators and administrators already familiar
with running a Solana Labs validator, as Firedancer heavily leans on the
same concepts and components. To get up to speed there, read the Solana
Labs [validators guide](https://docs.solana.com/running-validator).

The guide describes how to start and run a healthy Firedancer validator
node. The validator is under heavy development and should be considered
beta software, thank you for being on the bleeding edge.

## Help
Firedancer is beta software and you should expect hiccups when getting
started with, and when operating the validator. The Firedancer
development team can help diagnose any issues. The main place to discuss
Firedancer operational issues is the #firedancer channel in the [Solana
Tech discord](https://discord.gg/7kr7VmPH).

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
