# fd_dasm

A run time assembler for the sBPF transpiler, derived from
[DynASM](https://luajit.org/dynasm.html).

- `fd_dasm.py` preprocesses a `.dasc` file (C with embedded assembly)
  into C.  It only runs when the transpiler source changes; its output
  is checked in.
- `fd_dasm.h`, `fd_dasm_x86.h`, `fd_dasm_arm64.h` are the run time
  part, compiled into the transpiler.

```
make -C src/flamenco/vm/transpile generate test
```

## How it works

Lines starting with `|` are assembly, everything else is C.

```c
if( is_load ) {
  | mov Rq(dst), [r15+offset]
}
```

The generator assembles as much of each instruction as it can, and
collects the result in one constant array, the *action list*.  Operands
that are C expressions (`dst` and `offset` above) are not known yet, so
the action list holds an *action* in their place.  Each run of assembly
lines becomes one call:

```c
fd_dasm_put( DASM, 3254, (int const[]){ (int)((dst)), (int)(offset) } );
```

At run time, assembling is three passes over preallocated memory:

1. `fd_dasm_put` records the action list offset and the operand values.
2. `fd_dasm_link` resolves labels and computes the code size (on x86,
   branches shrink to their short form where possible).
3. `fd_dasm_encode` writes the machine code.

Errors (buffer full, operand out of range, undefined label) are sticky
and returned by `fd_dasm_link`, so the code between does not check.

## Syntax

| | |
|---|---|
| `\|.arch x64` | First statement.  `x64` or `arm64` |
| `\|.actionlist NAME` | Emit the action list array here |
| `\|.globals PREFIX` | Emit an enum of global labels here (`PREFIX_MAX` is the count) |
| `\|.globalnames NAME` | Emit an array of global label names here |
| `\|.type NAME, CTYPE, REG` | `NAME->field` is memory at `offsetof(CTYPE, field)` from `REG` |
| `\|.macro NAME, A, B` ... `\|.endmacro` | Statement macro.  Arguments replace whole words |
| `\|.align N` | Pad with nops to a multiple of N |
| `\|.byte`, `.word`, `.dword`, `.qword` | Raw data (x64) |
| `\|.long`, `.quad` | Raw data (arm64) |
| `\|->name:` | Global label, referenced as `->name` |
| `\|=>expr:` | pc label (index is a C expression), referenced as `=>expr` |
| `\|1:` ... `\|9:` | Local label, referenced as `<1` (previous) or `>1` (next) |
| `// ...` | Comment |

Operands are in Intel syntax on x64 and standard syntax on arm64.
Anything that is not a register, literal, or label is a C expression
evaluated at run time.  A register chosen at run time is written
`Rq(expr)`, `Rd(expr)`, `Rw(expr)`, `Rb(expr)`, `xmm(expr)` on x64 and
`Rx(expr)`, `Rw(expr)` on arm64.

`mov64 reg, expr` (x64) loads a 64 bit immediate.

## Adding an instruction

Add a template to `fd_dasm_x86_ops.py` or `fd_dasm_arm64_ops.py`.  The
template language is described at the top of each file.  Then add a use
to `fixtures/<arch>.dasc` and regenerate the expected output:

```
python3 fd_dasm.py -o fixtures/x86.c fixtures/x86.dasc
```

## Changing the action list encoding

The action numbers are defined twice, in `fd_dasm_<arch>.py` and
`fd_dasm_<arch>.h`.  Change both, bump `DASM_VERSION` /
`FD_DASM_VERSION`, and regenerate.
