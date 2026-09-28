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
* Frankendancer (`fdctl`) support is ending soon. If you run into issues
  with Frankendancer or `cargo`, please consider switching to full
  Firedancer `firedancer`.

## Configuring

### General Recommendations

* If there are errors during `firedancer configure init all --config
~/config.toml`, consider running `firedancer configure fini all --config
~/config.toml` to remove all existing configuration and try the `init`
command again. You can also re-run a specific configure stage, for
example, `firedancer configure init workspace --config ~/config.toml`.

* Make sure the `config.toml` specified during this command is the
same as the one specified with the `run` command. Also make sure
that the content is valid TOML.

* Read the output of the command carefully, `firedancer` often prints
out a helpful message that contains suggestions on how to resolve some
errors. Be sure to try them out!

## Running

### General Recommendations

* Make sure the `~/config.toml` being used is the same in the `configure`
and `run` commands.
