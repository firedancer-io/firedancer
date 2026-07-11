This directory contains a copy of the picohttpparser library.

This library is copied exactly from commit `66534e6`, with no
Firedancer specific modifications.  It does not compile under the
project's warning flags (sign-conversion, implicit-fallthrough), so
Local.mk compiles it with those flags stripped, like the other
vendored libraries.

For licensing information, refer to NOTICE in the root of this repo.
