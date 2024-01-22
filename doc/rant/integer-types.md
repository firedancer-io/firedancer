---
author: kbowers
date: 2023-01-30
---

**Q: Why define our own integer types instead of using `stdint.h`? I
don't see the advantage.**

There's a lot of nuanced discussion here (and a lot of it is written up
in `fd_util_base.h` and `test_util_base.c`).

A lot of it amounts to developers behave as though `int <> int32_t` and
so forth. `stdint.h / inttypes.h`, coming much too late to the party
(through no fault of their own ... this evil is on the standard
committee), are 2nd class citizens ... additional includes to bring in,
not used by the core language, unpleasantness with format strings, etc.

If I could go back in time and fix C/C++ at their inception, one of the
fixes would be to start with something `stdint`-like (and since it
doesn't have to work around the historical dubiousness, simplify it and
propagate it throughout the language pervasively).

But since that's a big change from what modern developer practice
(through no fault of their own ... they are saddled with the legacy), FD
takes a principle of least surprise approach and guarantee integer types
behave the way developers naturally behave (and rejects any platform
that doesn't behave like developers expect as too unsafe and
unproductive for real world use).

At which point the only thing `stdint.h` is giving is some width lexical
regularity across different types (like Nick noted above, which can be
useful and as I noted above, would be the "go back and time and fix the
language" ideal) and some more verbose aliases for types that are
already present.

That is, many moons ago, I basically got tired of cleaning up code that
would do things like `uint64_t x; ... printf( "x is %li\n", x );` and/or
losing weekends of my life tracking down really hard to find bugs when
such code didn't get cleaned up.

Such code breaks and then in the worst possible way. It will break ...
sometimes. And the breakage is often in ways that evade testing.

It might be at compile time (depending on build strictness, target
platform and compiler version ... like when you try to do what should be
trivial recompile under a new compiler or distro). It might be at
run-time (and then in most unpleasant ways from a security way POV due
to stack frame corruption that might not get tickled to cause it to fail
testing).

So I then became a convert to the idea that devs should use `stdint.h /
inttypes.h` for everything.

But I then learned the hard way it is a fool's errand to try to convince
other developers to religiously to do this (nobody likes typing `printf(
"x is " UINT64_FMT "\n", x );` over the above ... feels like a giant
pile of fail). Practically speaking, I couldn't even convince myself ...
nearly every aspect of development reduces friction to use the core
types. Such a PITA in testing / debugging and easy to slip up in
deployment to use these alternatives.

And because most everything in libc / POSIX predates `stdint.h` (and the
most later stuff carried on the tradition), everything looks like it is
using superficially different types even if you get religion.

So developers get sloppy and silent implicit conversions start appearing
everywhere. And nobody can turn on things like `-Wconversion` to clean
it up because its false positive rate is too high. Worse, nobody is
really sure which are false positives because the documentation isn't
there to make it straightforward to tell a narrowing conversion is safe
and/or necessary for an API / ABI or is actually a latent bug.

So what FD is doing is my current thinking. Cut through the BS and
guarantee the target platform core types behave like developers expect
and then stick within that system.

Lot less code line noise from developers trying to deal with the various
subtle differences, predictable and expected behaviors, stricter
compilation / linting, less bug attack surface area, quicker to write
debugging and logging format strings (more) readably, etc.

Against this background, `stdint.h / inttypes.h` become superfluous and
I'd prefer it to not creep into exposed interfaces.

But if there is some readability benefit to an implementation, the
environment does strictly guarantee uint32_t <> uint, uint64_t <> ulong,
etc and using them will not break the water tightness.
