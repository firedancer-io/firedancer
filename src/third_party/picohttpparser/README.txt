https://github.com/h2o/picohttpparser

Copied exactly from commit 54413dc68acd3aca70317d3c0a8c1d45819c9de2,
with no Firedancer specific modifications.  It does not compile under the
project's warning flags (sign-conversion, implicit-fallthrough), so
Local.mk compiles it with those flags stripped, like the other
vendored libraries.

For licensing information, refer to NOTICE in the root of this repo.
