---
author: kbowers
date: 2023-03-15
---

There's a lot of history around `-fomit-frame-pointer`.

x86 has always been severely register-starved versus other architectures and it was really bad pre-x86_64 (the larger register file in x86_64 was as at least important as having 64-bit registers).

So, in the way, way back on Linux and x86, you'd use this compile flag in an optimized build to make an extra register available for code. It was pretty dramatic improvement in real world performance to have an extra register when you only had O(6) general purpose-ish registers available (eax,ebx,ecx,edx,edi,esi) ... e.g. fewer spills to stack ("-ish" because the x86 ISA does have lots of hardcoded usages for these registers).

This flag wasn't a pure benefit though. It made debugging binaries more difficult as it was more difficult for a debugger to inspect what was going on in the stack.
By comparison, non-x86 at the time typically had O(16 to 32) truly general purposes registers (so the potential benefit was lower) and the way non-Linux OS / ABIs / etc/ managed stack, handled function calls, etc could affect the cost (from irrelevant to impossible).
Since then, debuggers on Linux / binary file debugging symbol info / etc got more sophisticated. This makes the debugging visibility cost of this flag lower. At the same time, x86_64 has a larger (but still not great) register file, the benefit is lower too. And architectures and O/S might have evolved too.
The upshot of all this, -fomit-frame-pointer is somewhere between useful and moot on modern Linux / x86_64 (and, if somebody has some compelling reason to require or remove it on modern Linux / x86_64, totally open to it).

As for non-x86 and/or non-Linux, it is probably somewhere between annoying to mildly useful due to analogous considerations specific that architecture and OS (and/or there might be some other architecture specific flags in this vein).
The upshot being, -fomit-frame-pointer it certainly isn't a requirement to have and should be viewed much much as a platform specific flag. It is debatable how useful it is on Linux / x86_64 these days. And it is even more debatable on non-Linux and/or non-x86_64.
