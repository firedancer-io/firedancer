# [Firedancer](https://jumpcrypto.com/firedancer/) 🔥💃

Firedancer is a new validator client for Solana.

* **Fast** Designed from the ground up to be *fast*. The concurrency
model is borrowed from the low latency trading space, and the code
contains many novel high performance reimplementations of core Solana
primitives.
* **Secure** The architecture of the validator allows it to run with a
highly restrictive sandbox and almost no system calls.
* **Independent** Firedancer is written from scratch. This brings client
diversity to the Solana network and helps it stay resilient to supply
chain attacks in build tooling or dependencies.

## Documentation
If you are an operator or looking to run the validator, see the Getting
Started guide in the [Firedancer docs](https://firedancer-io.github.io/)

## Developing
The below describes building Frankendancer from scratch and running it
optimized on a stock Linux image. You will need basic development tools
like `make`, `gcc` along with `rustc`, and `clang`.

Frankendancer currently only supports Linux, and requires a kernel newer
than v5.7 to build.

```bash
$ sudo dnf groupinstall development
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then you can clone and build the application from source,

```bash
$ git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
$ cd firedancer
$ ./deps.sh
$ make -j run
```

The `make run` target runs the `fddev dev` command. This development
command will ensure your system is configured correctly before creating
a genesis block, some keys, a faucet, and then starting a validator on
the local machine. `fddev` will use `sudo` to make privileged changes to
system configuration where needed. If `sudo` is not available, you may
need to run the command as root.

By default `fddev` will create a new development cluster, if you wish to
join this cluster with other validators, you can define
`[rpc.entrypoints]` in the configuration file to point at your first
validator and run `fddev dev` again.

## License
Firedancer is available under the [Apache 2
license](https://www.apache.org/licenses/LICENSE-2.0). Firedancer also
includes external libraries that are available under a variety of
licenses. See [LICENSE](LICENSE) for the full license text.
