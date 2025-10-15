# Tracing

The Firedancer system environment provides a low-overhead structured
logging (tracing) solution for profiling and in-vivo debugging.

Instrumented tiles export trace information in [Fuchsia trace format](https://fuchsia.dev/fuchsia-src/reference/tracing/trace-format) to shared memory rings.

These traces are then optionally captured to an `.fxt` file.
`.fxt` files can be viewed in [Perfetto](https://perfetto.dev/).

This page explains the design and implementation details of the
Firedancer tracing system in detail.

## Design

Firedancer's tracing solution was built to solve the following problems:

- **Profiling**: Capture application-wide events and present them in a
  flamegraph/perf-like format
- **Data tracing**: Trace bits of information and async processes
  through multiple tiles/threads
- **Machine readable**: Dump data in easy-to-read/standard formats,
  enforce schemas
- **Human readable**: Optimize for good developer UX, support popular
  existing tooling

... while optimizing for the following features ...

- **Simplicity** (as always)
- **Throughput**: Firedancer components can handle O(1e6) TPS, so a
  tracing engine should be built to handle at least O(1e7) events
- **Overhead**: Minimize code bloat and resource usage of instrumented
  code
- **Accuracy**: Log timestamps with hardware-TSC level accuracy

We can derive some properties from the requirements above:

- Encode information in a simple and compact **binary format**
- Use low-overhead **shared memory queues** to export trace information
  from app tiles (zero syscalls, lockfree, NOC friendly, etc)
- Use this format both internally (in shared memory) and externally
  (in files, over the network)
- Try to use a standard with existing integrations, avoid rolling a
  custom format

## Trace format

At the time of writing (2025-Oct), the Fuchsia trace format meets above
criteria well.  It is [well specified](https://fuchsia.dev/fuchsia-src/reference/tracing/trace-format),
easy to produce, and compact (heavily uses dictionary based compression
for common strings).

The [Perfetto trace viewer](https://ui.perfetto.dev/) natively supports
Fuchsia trace format.

## Instrumentation

Each production tile is given an exclusive trace ring buffer
(`fd_fxt_cache`) in a metrics shared memory region.  The tile can log
into this buffer lockfree.

To instrument a piece of production code, first declare the schema in
`tracing.xml`.  Note that this schema language is custom, see [below](#schema).

```xml
<category name="progcache">
  <event type="instant" name="progcache_pull">
    <arg type="u32" name="result" />
  </event>
</category>
```

The above will generate corresponding C functions to generate trace
events.  These functions can be called from any Firedancer code with no
initialization necessary.

```c
fd_trace_progcache_pull( /* result */ 1U );
```

By default, trace events get sent to a small thread-local ring buffer.
For code running in Firedancer production tiles, the topology system
automatically sets up appropriate shared memory regions, and directs
trace events to there instead.

## Production overhead

The generated tracing code is carefully engineered for minimal prod
overhead.

- Ban BTB usage, i.e. single-shot block of inlined x86 instructions,
  no loops, no branches, no call instructions
- Minimize code footprint
- Minimize compiler artifacts: no assembly hacks, to avoid inhibiting
  the optimizer, and allow the compiler to interleave trace-related
  instructions with production code (maximizes resource efficiency).
  Uses a compiler fence, though.
- Avoid pipeline stalls: aim for good ILP, no fences/barriers, no lock
  prefixes, no atomic ops
- Avoid resource pressure: pack information densely, i.e. multiple
  trace records per cache line
- Avoid cache coherence traps: pace readers of FTF data to avoid cache
  line bouncing

## Shared memory protocol

Recall that each app thread produces trace events into its own shared
memory queue.  There exist reader threads (typically only one) that
retrieve records published into such queues.

The tracing engine currently uses an mcache/dcache pair to store trace
records.  This may be replaced with a more efficient protocol in the
future.

The `frag_meta` record descriptor is used as follows:

- `seq`: sequence number
- `sig`: inline word 0
- `chunk`: offset into dcache
- `sz`: entry size (multiple of 8)
- `ctl`
  - 0 implies inline record
  - 1 implies external record
- `tsorig`: inline word 1
- `tspub`: inline word 2

A typical ring is 64 KiB large (1024 depth).

## Schema

All trace schemas are centrally defined in the `tracing.xml` file.
The schema of this XML file is as follows:

- `category`: defines an event category
  - Attribute `name`: category name (e.g. `progcache`)
  - Children are of types: `event`
- `event`: declares an event type
  - Attribute `type`: one of `instant`, `duration`
  - Attribute `name`: event name (e.g. `progcache_pull`)
  - Children are of types: `arg`
- `arg`: declares an event arg
  - Attribute `type`: one of `s32`, `u32`, `s64`, `u64`, `f64`, `string`, `pointer`, `bool`
  - Attribute `name`: argument name (e.g. `result`)

## String Dictionary

`fd_trace` uses a pre-compiled dictionary of strings for performance.
These include event categories, event names, and event attributes.

The string dictionary is at `fd_trace_strings.c` and is generated by
`tracing.xml` / `gen_tracing.py`.

Fuchsia's trace format has a hardcoded dictionary size limit of 32767
entries, which is enough that we will practically never run out of
space.
