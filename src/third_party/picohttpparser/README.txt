https://github.com/h2o/picohttpparser

Copied exactly from commit 66534e6a48d67a3d9ddfeb5bd2c922f498d314ae,
with no Firedancer specific modifications.  It does not compile under the
project's warning flags (sign-conversion, implicit-fallthrough), so
Local.mk compiles it with those flags stripped, like the other
vendored libraries.

For licensing information, refer to NOTICE in the root of this repo.
