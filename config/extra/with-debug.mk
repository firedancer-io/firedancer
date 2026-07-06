CPPFLAGS+=-g3
CPPFLAGS+=-fno-omit-frame-pointer
LDFLAGS+=-rdynamic

# At -O3, GCC's variable location tracking (the pass that records which
# register/stack slot holds each source variable at each PC range) is by
# far the most expensive part of debug info generation: up to ~50% of
# compile time on large vectorized TUs (reedsol, bn254) and ~18% of the
# .debug_* bytes (.debug_loclists).  Disable it: line tables, types,
# frames, unwind info and macro info are all unaffected, so backtraces,
# breakpoints, perf/flamegraphs and core triage still work; only
# "print <var>" fidelity inside optimized frames degrades (which is
# already unreliable at -O3).  Clang has no such flag (var tracking is
# cheap there), so keep this GCC only.
ifdef FD_USING_GCC
CPPFLAGS+=-fno-var-tracking
endif
