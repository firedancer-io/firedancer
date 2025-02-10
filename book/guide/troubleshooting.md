# Troubleshooting

This page has a collection of common troubleshooting steps when operators
encounter errors while building and running Frankendancer. If these do
not address the problem, send a message in the `#firedancer-operators`
channel on the Solana Tech Discord or file an issue on GitHub.

## Building

### General Recommendations

* It is always a good idea to retry building everything again from scratch.
Do a fresh clone of the repository, following the instructions in the
[Getting Started](./getting-started.md#prerequisites) guide. Remember to
check if you're using a supported compiler and to run `./deps.sh`!

* If you're updating an existing repository clone, be sure to update
the solana submodule _after_ pulling the latest changes. For example:

```sh [bash]
~/firedancer $ git fetch
~/firedancer $ git checkout __FD_LATEST_VERSION__
~/firedancer $ git submodule update
```

### Specific Errors

* Missing `cargo` binary from rust toolchain

```sh [bash]
error: the 'cargo' binary, normally provided by the 'cargo' component, is not applicable to the '1.75.0-x86_64-unknown-linux-gnu' toolchain
+ exec cargo +1.75.0 build --profile=release-with-debug --lib -p agave-validator
error: the 'cargo' binary, normally provided by the 'cargo' component, is not applicable to the '1.75.0-x86_64-unknown-linux-gnu' toolchain
make: *** [src/app/fdctl/Local.mk:107: cargo-validator] Error 1
```

This typically happens due to a race condition between trying to install the
correct version of the rust toolchain and using it. Separately re-installing
the toolchain fixes it (replace `1.75.0` with the appropriate version):

```sh [bash]
rustup toolchain uninstall 1.75.0-x86_64-unknown-linux-gnu
rustup toolchain install 1.75.0-x86_64-unknown-linux-gnu
```

## Configuring

### General Recommendations

* If there are errors during `fdctl configure init all --config
~/config.toml`, consider running `fdctl configure fini all --config
~/config.toml` to remove all existing configuration and try the `init`
command again. You can also re-run a specific configure stage, for
example, `fdctl configure init workspace --config ~/config.toml`.

* Make sure the `config.toml` specified during this command is the
same as the one specified with the `run` command. Also make sure
that the content is valid TOML.

* Read the output of the command carefully, `fdctl` often prints out
a helpful message that contains suggestions on how to resolve some
errors. Be sure to try them out!

## Running

### General Recommendations

* Make sure the `~/config.toml` being used is the same in the `configure`
and `run` commands.
