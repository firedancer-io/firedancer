# Firedancer
This introduction is under construction...

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
