#!/usr/bin/env python3

# THE OUTPUT OF THIS SCRIPT HAS TO BE AUDITED.
# We have the choice to spend a lot of energy verifying this compiler or
# spend a little bit of energy each time verifying its outputs.  Given that
# the code that it generates is succinct and commented, we picked the
# latter.

# This file contains a naive compiler that turns symbolic expressions into
# cBPF code.  Instead of targeting cBPF, the compiler targets C header
# files. This has the advantage of allowing the use of C constants, as long
# as they are in scope.

from __future__ import annotations

import os
import sys
from typing import NoReturn, TextIO, TypeGuard, Union, Tuple

# Arguments are passed to Linux syscalls through 64-bit registers. When
# that syscall only uses the bottom 32-bits, like for an int, Linux ignores
# the top 32-bits no matter what they are. On the other hand, Seccomp sees
# the full 64-bits of the argument in its policies.
#
# Consider the example where close() is called with a bad argument, where
# the top half is set to garbage and the bottom half is a valid file
# descriptor. We want to prevent a certain file descriptor from being
# closed, so we create a rule that says close: if (fd == 2) deny.
#
# Our policy will check both the top and bottom bits, and say that fd is
# not equal to 2, as the top bits are set, and allow the syscall, while
# Linux will cut off the top bits and close fd 2.
#
# We keep this table of prototypes for syscalls in order to decide whether
# we should emit a 32-bit or a 64-bit check for that argument.
SYSCALL_ARGS = {
    #                      arg0    arg1     arg2    arg3    arg4     arg5
    "accept4":         (  "int", "long",  "long",  "int",   None,    None  ),
    "bind":            (  "int", "long",   "int",   None,   None,    None  ),
    "clock_nanosleep": (  "int",  "int",  "long", "long",   None,    None  ),
    "close":           (  "int",   None,    None,   None,   None,    None  ),
    "connect":         (  "int", "long",   "int",   None,   None,    None  ),
    "copy_file_range": (  "int", "long",   "int", "long", "long",   "int"  ),
    "exit_group":      (  "int",   None,    None,   None,   None,    None  ),
    "exit":            (  "int",   None,    None,   None,   None,    None  ),
    "fallocate":       (  "int",  "int",  "long", "long",   None,    None  ),
    "fcntl":           (  "int",  "int",  "long",   None,   None,    None  ),
    "fstat":           (  "int", "long",    None,   None,   None,    None  ),
    "fsync":           (  "int",   None,    None,   None,   None,    None  ),
    "ftruncate":       (  "int", "long",    None,   None,   None,    None  ),
    "getsockopt":      (  "int",  "int",   "int", "long", "long",    None  ),
    "ioctl":           (  "int",  "int",  "long",   None,   None,    None  ),
    "kill":            (  "int",  "int",    None,   None,   None,    None  ),
    "lseek":           (  "int", "long",   "int",   None,   None,    None  ),
    "madvise":         ( "long", "long",   "int",   None,   None,    None  ),
    "poll":            ( "long",  "int",   "int",   None,   None,    None  ),
    "ppoll":           ( "long",  "int",  "long", "long", "long",    None  ),
    "pread64":         (  "int", "long",  "long", "long",   None,    None  ),
    "pselect6":        (  "int", "long",  "long", "long", "long",  "long"  ),
    "preadv2":         (  "int", "long",   "int", "long", "long",   "int"  ),
    "pwrite64":        (  "int", "long",  "long", "long",   None,    None  ),
    "pwritev2":        (  "int", "long",   "int", "long", "long",   "int"  ),
    "read":            (  "int", "long",  "long",   None,   None,    None  ),
    "recvfrom":        (  "int", "long",  "long",  "int", "long",  "long"  ),
    "recvmmsg":        (  "int", "long",   "int",  "int", "long",    None  ),
    "recvmsg":         (  "int", "long",   "int",   None,   None,    None  ),
    "renameat":        (  "int", "long",   "int", "long",   None,    None  ),
    "renameat2":       (  "int", "long",   "int", "long",  "int",    None  ),
    "sendmmsg":        (  "int", "long",   "int",  "int",   None,    None  ),
    "sendmsg":         (  "int", "long",   "int",   None,   None,    None  ),
    "sendto":          (  "int", "long",  "long",  "int", "long",   "int"  ),
    "setsockopt":      (  "int",  "int",   "int", "long",  "int",    None  ),
    "shutdown":        (  "int",  "int",    None,   None,   None,    None  ),
    "socket":          (  "int",  "int",   "int",   None,   None,    None  ),
    "wait4":           (  "int", "long",   "int", "long",   None,    None  ),
    "write":           (  "int", "long",  "long",   None,   None,    None  ),
    "writev":          (  "int", "long",  "long",   None,   None,    None  ),
}


def arg_is_32bit(syscall: str, n: int) -> bool:
    if syscall not in SYSCALL_ARGS:
        die(f"syscall '{syscall}' not in argument table")
    types = SYSCALL_ARGS[syscall]
    if n < 0 or n > 5:
        die(f"argument index {n} out of range [0, 5]")
    t = types[n]
    if t is None:
        die(f"argument {n} of syscall '{syscall}' is not typed in argument table")
    return t == "int"


class Symbol(str):
    pass


def die(msg: str) -> NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(1)


def tokenize(expr: str) -> list[str | Symbol]:
    out = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch.isspace():
            i += 1
        elif ch in "()":
            out.append(ch)
            i += 1
        elif ch == '"':
            i += 1
            val = ""
            while i < len(expr):
                ch = expr[i]
                if ch == "\\":
                    if i + 1 >= len(expr):
                        raise ValueError("unterminated escape in string")
                    val += expr[i + 1]
                    i += 2
                elif ch == '"':
                    out.append(val)
                    i += 1
                    break
                else:
                    val += ch
                    i += 1
            else:
                raise ValueError("unterminated string")
        else:
            start = i
            while i < len(expr) and not expr[i].isspace() and expr[i] not in "()":
                i += 1
            out.append(Symbol(expr[start:i]))
    return out


def parse_atom(tok: str | Symbol) -> Atom:
    if type(tok) is not Symbol:
        return tok
    try:
        return int(tok, 10)
    except ValueError:
        return tok


Atom = Union[int, str, Symbol]
Imm = Union[int, str, Symbol]
Expr = Union[Atom, Tuple["Expr", ...]]


def parse_tokens(tokens: list[str | Symbol], i: int = 0) -> tuple[Expr, int]:
    if i >= len(tokens):
        raise ValueError("unexpected end of expression")
    tok = tokens[i]
    if tok == "(":
        i += 1
        vals = []
        while i < len(tokens) and tokens[i] != ")":
            val, i = parse_tokens(tokens, i)
            vals.append(val)
        if i >= len(tokens):
            raise ValueError("unterminated list")
        return tuple(vals), i + 1
    if tok == ")":
        raise ValueError("unexpected ')'")
    return parse_atom(tok), i + 1


def parse_expr(expr: str) -> Expr:
    tokens = tokenize(expr)
    if not tokens:
        raise ValueError("empty expression")
    val, i = parse_tokens(tokens)
    if i != len(tokens):
        raise ValueError("trailing tokens")
    return val


def strip_comments(lines: list[str]) -> list[str]:
    return [line for line in lines if not line.lstrip().startswith("#")]


def join_continuations(lines: list[str]) -> list[str]:
    out : list[str] = []
    for line in lines:
        if line.startswith((" ", "\t")) and out:
            out[-1] += line
        else:
            out.append(line)
    return out


def policy_lines(raw_lines: list[str]) -> list[str]:
    return [
        line.strip()
        for line in join_continuations(strip_comments(raw_lines))
        if line.strip()
    ]


def split_policy_line(line: str, line_no: int) -> tuple[str, str | None]:
    parts = line.split(":", 1)
    if len(parts) == 1:
        return parts[0].strip(), None
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    die(f"malformed policy line {line_no}")


def parse_signature(sigline: str) -> set[str]:
    if sigline == "noarg":
        return set()
    params: set[str] = set()
    for raw_param in sigline.split(","):
        raw_param = raw_param.strip()
        if not raw_param:
            die("empty parameter in signature")
        pieces = raw_param.split()
        if len(pieces) < 2:
            die(f"malformed parameter (missing name or type): '{raw_param}'")
        name = pieces[-1].strip("*")
        if not name:
            die(f"empty parameter name in: '{raw_param}'")
        if name in params:
            die(f"duplicate parameter name: '{name}'")
        ctype = " ".join(pieces[:-1])
        if ctype not in ("uint",):
            die(f"invalid parameter type: {ctype}")
        params.add(name)
    if not params:
        die("signature has no parameters (use 'noarg' for parameterless policies)")
    return params


def is_arg(expr: Expr) -> TypeGuard[tuple]:
    return isinstance(expr, tuple) and len(expr) == 2 and str(expr[0]) == "arg"


def arg_no(expr: Expr) -> int:
    if not is_arg(expr):
        raise ValueError("expected (arg N)")
    n = expr[1]
    if type(n) is not int or n < 0 or n > 5:
        raise ValueError("argument number must be an integer in [0, 5]")
    return n


class ImmWords:
    def __init__(self, lo: str, hi: str) -> None:
        self.lo = lo
        self.hi = hi


def imm_words(expr: Imm, params: set[str]) -> ImmWords:
    assert isinstance(expr, (int, str, Symbol)), f"expected int, str, or Symbol, got {type(expr)}"
    if type(expr) is int:
        if expr < 0:
            die(f"negative immediate not supported: {expr}")
        if expr >= (1 << 32):
            die(f"imm expr too large: {expr}")
        return ImmWords(f"0x{expr:08x}U", "0x00000000U")

    text = str(expr)
    if type(expr) is Symbol and text in params:  # all params are uint
        return ImmWords(f"((uint)({text}))", "0x00000000U")

    return ImmWords(
        f"FD_SECCOMP_ARG_LO({text})",
        f"FD_SECCOMP_ARG_HI({text})",
    )


class Stmt:
    def __init__(self, text: str, comment: str | None = None) -> None:
        self.text = text
        self.comment = comment


class Jump:
    def __init__(self, op: str, k: str, jt: str | int, jf: str | int, comment: str | None = None) -> None:
        self.op = op
        self.k = k
        self.jt = jt
        self.jf = jf
        self.comment = comment


class Label:
    def __init__(self, name: str) -> None:
        self.name = name


class Program:
    def __init__(self) -> None:
        self.items: list[Stmt | Jump | Label] = []
        self.label_id: int = 0

    def new_label(self, prefix: str = "lbl") -> str:
        self.label_id += 1
        return f"{prefix}_{self.label_id}"

    def label(self, name: str) -> None:
        if any(isinstance(item, Label) and item.name == name for item in self.items):
            raise ValueError(f"duplicate label '{name}'")
        self.items.append(Label(name))

    def stmt(self, text: str, comment: str | None = None) -> None:
        self.items.append(Stmt(text, comment))

    def jump(self, op: str, k: str, jt: str | int, jf: str | int, comment: str | None = None) -> None:
        self.items.append(Jump(op, k, jt, jf, comment))

    def ret(self, value: str, comment: str | None = None) -> None:
        self.stmt(f"BPF_STMT( BPF_RET | BPF_K, {value} )", comment)

    def load_abs(self, expr: str, comment: str | None = None) -> None:
        self.stmt(f"BPF_STMT( BPF_LD | BPF_W | BPF_ABS, {expr})", comment)

    def load_arg_lo(self, n: int) -> None:
        self.load_abs(f"FD_SECCOMP_ARG_LO_OFFSET({n})", f"arg {n} low 32 bits")

    def load_arg_hi(self, n: int) -> None:
        self.load_abs(f"FD_SECCOMP_ARG_HI_OFFSET({n})", f"arg {n} high 32 bits")

    def instruction_count(self) -> int:
        return sum(1 for item in self.items if not isinstance(item, Label))

    def render_target(self, target: str | int, pc: int, labels: dict[str, int], max_offset: int | None = None) -> str:
        if isinstance(target, int):
            return str(target)
        if target not in labels:
            raise ValueError(f"unknown label {target}")
        off = labels[target] - pc - 1
        if off < 0:
            raise ValueError(f"backward jump to {target}")
        if max_offset is not None and off > max_offset:
            raise ValueError(
                f"jump to {target} from instruction {pc} has offset {off}, max {max_offset}"
            )
        return f"/* {target} */ {off}"

    def render(self) -> list[str]:
        labels: dict[str, int] = {}
        pc = 0
        for item in self.items:
            if isinstance(item, Label):
                if item.name in labels:
                    raise ValueError(f"duplicate label '{item.name}'")
                labels[item.name] = pc
            else:
                pc += 1

        line_labels: dict[int, str] = {}
        for name, idx in labels.items():
            assert idx not in line_labels, f"multiple labels at instruction {idx}: {line_labels[idx]}, {name}"
            line_labels[idx] = name

        lines = []
        pc = 0
        for item in self.items:
            if isinstance(item, Label):
                continue
            if pc in line_labels:
                lines.append(f"//  {line_labels[pc]}:")
            if item.comment:
                lines.append(f"    /* {item.comment} */")
            if isinstance(item, Stmt):
                lines.append(f"    {item.text},")
            elif isinstance(item, Jump):
                jt = self.render_target(item.jt, pc, labels, 255)
                jf = self.render_target(item.jf, pc, labels, 255)
                lines.append(f"    BPF_JUMP( {item.op}, {item.k}, {jt}, {jf} ),")
            pc += 1
        return lines


def emit_arg_eq(prog: Program, n: int, imm: Imm, label_t: str, label_f: str, params: set[str], syscall: str) -> None:
    words = imm_words(imm, params)
    if arg_is_32bit(syscall, n):
        prog.load_arg_lo(n)
        prog.jump("BPF_JMP | BPF_JEQ | BPF_K", words.lo, label_t, label_f)
    else:
        hi_ok = prog.new_label("arg_hi_eq")
        prog.load_arg_hi(n)
        prog.jump("BPF_JMP | BPF_JEQ | BPF_K", words.hi, hi_ok, label_f)
        prog.label(hi_ok)
        prog.load_arg_lo(n)
        prog.jump("BPF_JMP | BPF_JEQ | BPF_K", words.lo, label_t, label_f)


def emit_arg_cmp(prog: Program, op: str, n: int, imm: Imm, label_t: str, label_f: str, params: set[str], syscall: str) -> None:
    if op == "eq":
        emit_arg_eq(prog, n, imm, label_t, label_f, params, syscall)
        return

    words = imm_words(imm, params)

    if arg_is_32bit(syscall, n):
        prog.load_arg_lo(n)
        if op == "<":
            prog.jump("BPF_JMP | BPF_JGE | BPF_K", words.lo, label_f, label_t)
        elif op == "<=":
            prog.jump("BPF_JMP | BPF_JGT | BPF_K", words.lo, label_f, label_t)
        elif op == ">":
            prog.jump("BPF_JMP | BPF_JGT | BPF_K", words.lo, label_t, label_f)
        elif op == ">=":
            prog.jump("BPF_JMP | BPF_JGE | BPF_K", words.lo, label_t, label_f)
        else:
            raise ValueError(f"unsupported comparison {op}")
        return

    mid = prog.new_label("arg_cmp")
    eq = prog.new_label("arg_cmp_eq")
    prog.load_arg_hi(n)

    if op == "<":
        prog.jump("BPF_JMP | BPF_JGT | BPF_K", words.hi, label_f, mid)
        prog.label(mid)
        prog.jump("BPF_JMP | BPF_JEQ | BPF_K", words.hi, eq, label_t)
        prog.label(eq)
        prog.load_arg_lo(n)
        prog.jump("BPF_JMP | BPF_JGE | BPF_K", words.lo, label_f, label_t)
    elif op == "<=":
        prog.jump("BPF_JMP | BPF_JGT | BPF_K", words.hi, label_f, mid)
        prog.label(mid)
        prog.jump("BPF_JMP | BPF_JEQ | BPF_K", words.hi, eq, label_t)
        prog.label(eq)
        prog.load_arg_lo(n)
        prog.jump("BPF_JMP | BPF_JGT | BPF_K", words.lo, label_f, label_t)
    elif op == ">":
        prog.jump("BPF_JMP | BPF_JGT | BPF_K", words.hi, label_t, mid)
        prog.label(mid)
        prog.jump("BPF_JMP | BPF_JEQ | BPF_K", words.hi, eq, label_f)
        prog.label(eq)
        prog.load_arg_lo(n)
        prog.jump("BPF_JMP | BPF_JGT | BPF_K", words.lo, label_t, label_f)
    elif op == ">=":
        prog.jump("BPF_JMP | BPF_JGT | BPF_K", words.hi, label_t, mid)
        prog.label(mid)
        prog.jump("BPF_JMP | BPF_JEQ | BPF_K", words.hi, eq, label_f)
        prog.label(eq)
        prog.load_arg_lo(n)
        prog.jump("BPF_JMP | BPF_JGE | BPF_K", words.lo, label_t, label_f)
    else:
        raise ValueError(f"unsupported comparison {op}")


def invert_cmp(op: str) -> str:
    return {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "eq": "eq"}[op]


def emit_expr(prog: Program, expr: tuple, label_t: str, label_f: str, params: set[str], syscall: str) -> None:
    if type(expr) is not tuple or not expr:
        raise ValueError(f"unsupported expression {expr}")

    op = str(expr[0])
    if op == "not":
        if len(expr) != 2:
            raise ValueError("not expects one argument")
        emit_expr(prog, expr[1], label_f, label_t, params, syscall)
    elif op == "and":
        if len(expr) < 2:
            raise ValueError("and expects arguments")
        for idx, child in enumerate(expr[1:]):
            if idx == len(expr) - 2:
                emit_expr(prog, child, label_t, label_f, params, syscall)
            else:
                next_label = prog.new_label("and")
                emit_expr(prog, child, next_label, label_f, params, syscall)
                prog.label(next_label)
    elif op == "or":
        if len(expr) < 2:
            raise ValueError("or expects arguments")
        for idx, child in enumerate(expr[1:]):
            if idx == len(expr) - 2:
                emit_expr(prog, child, label_t, label_f, params, syscall)
            else:
                next_label = prog.new_label("or")
                emit_expr(prog, child, label_t, next_label, params, syscall)
                prog.label(next_label)
    elif op in ("eq", "<", "<=", ">", ">="):
        if len(expr) != 3:
            raise ValueError(f"{op} expects two arguments")
        lhs, rhs = expr[1], expr[2]
        if is_arg(lhs) and not is_arg(rhs):
            emit_arg_cmp(prog, op, arg_no(lhs), rhs, label_t, label_f, params, syscall)
        elif is_arg(rhs) and not is_arg(lhs):
            emit_arg_cmp(
                prog,
                invert_cmp(op),
                arg_no(rhs),
                lhs,
                label_t,
                label_f,
                params,
                syscall,
            )
        else:
            raise ValueError(f"unsupported comparison operands {expr}")
    elif op == "arg":
        prog.load_arg_lo(arg_no(expr))
    else:
        raise ValueError(f"unknown operator {op}")


def compile_policy(entries: list[tuple[int, tuple[str, str | None]]], params: set[str]) -> Program:
    prog = Program()
    checked : list[tuple] = []
    seen = set()

    prog.load_abs("( offsetof( struct seccomp_data, arch ) )", "validate architecture")
    prog.jump("BPF_JMP | BPF_JEQ | BPF_K", "ARCH_NR", 0, "RET_KILL_PROCESS")
    prog.load_abs("( offsetof( struct seccomp_data, nr ) )", "load syscall number")

    for line_no, (syscall, expr_text) in entries:
        if syscall in seen:
            die(f"duplicate syscall entry for {syscall} on line {line_no}")
        seen.add(syscall)
        if expr_text is None:
            prog.jump(
                "BPF_JMP | BPF_JEQ | BPF_K",
                f"SYS_{syscall}",
                "RET_ALLOW",
                0,
                f"allow {syscall}",
            )
        else:
            label = f"check_{syscall}"
            prog.jump(
                "BPF_JMP | BPF_JEQ | BPF_K",
                f"SYS_{syscall}",
                label,
                0,
                f"check {syscall}",
            )
            checked.append((syscall, parse_expr(expr_text)))

    prog.label("RET_KILL_PROCESS")
    prog.ret("SECCOMP_RET_KILL_PROCESS", "default deny")
    prog.label("RET_ALLOW")
    prog.ret("SECCOMP_RET_ALLOW", "allow")

    for syscall, expr in checked:
        allow = f"{syscall}_ALLOW"
        kill = f"{syscall}_KILL"
        prog.label(f"check_{syscall}")
        emit_expr(prog, expr, allow, kill, params, syscall)
        prog.label(kill)
        prog.ret("SECCOMP_RET_KILL_PROCESS")
        prog.label(allow)
        prog.ret("SECCOMP_RET_ALLOW")

    prog.render()
    return prog


def header_guard(rel_dst: str) -> str:
    child = rel_dst.replace("/", "_").replace(".", "_")
    return f"HEADER_fd_{child}"


def util_include_path(rel_dst: str) -> str:
    return os.path.join(*([".."] * rel_dst.count("/")), "src/util/fd_util_base.h")


def write_lines(out: TextIO, lines: list[str]) -> None:
    out.write("\n".join(lines))
    out.write("\n")


def render_header(out: TextIO, src_path: str, sigline: str, filter_name: str, prog: Program) -> None:
    dst_rel = os.path.join(
        os.path.dirname(src_path), "generated", filter_name + "_seccomp.h"
    )
    if dst_rel.startswith("./"):
        dst_rel = dst_rel[2:]
    dst_rel = os.path.relpath(dst_rel, os.getcwd())
    guard = header_guard(dst_rel)
    util_path = util_include_path(dst_rel)
    instr_cnt = prog.instruction_count()

    constructor = f"static void populate_sock_filter_policy_{filter_name}( ulong out_cnt, struct sock_filter out[ static {instr_cnt} ]"
    if sigline == "noarg":
        constructor = f"{constructor} ) {{"
    else:
        constructor = f"{constructor}, {sigline} ) {{"

    write_lines(
        out,
        [
            "/* THIS FILE WAS GENERATED BY generate_filters.py. DO NOT EDIT BY HAND! */",
            f"#ifndef {guard}",
            f"#define {guard}",
            "",
            "#if defined(__linux__)",
            "",
            f'#include "{util_path}"',
            "#include <linux/audit.h>",
            "#include <linux/capability.h>",
            "#include <linux/filter.h>",
            "#include <linux/seccomp.h>",
            "#include <linux/bpf.h>",
            "#include <linux/unistd.h>",
            "#include <sys/syscall.h>",
            "#include <signal.h>",
            "#include <stddef.h>",
            "",
            "#if defined(__i386__)",
            "# define ARCH_NR  AUDIT_ARCH_I386",
            "#elif defined(__x86_64__)",
            "# define ARCH_NR  AUDIT_ARCH_X86_64",
            "#elif defined(__aarch64__)",
            "# define ARCH_NR AUDIT_ARCH_AARCH64",
            "#else",
            '# error "Target architecture is unsupported by seccomp."',
            "#endif",
            "",
            "#define FD_SECCOMP_ARG_LO_OFFSET(argno) ( offsetof( struct seccomp_data, args[(argno)] ) )",
            "#define FD_SECCOMP_ARG_HI_OFFSET(argno) ( offsetof( struct seccomp_data, args[(argno)] ) + 4U )",
            "",
            "#define FD_SECCOMP_ARG_LO(x) ((uint)(((ulong)(uint)(int)(x)      ) & 0xffffffffUL))",
            "#define FD_SECCOMP_ARG_HI(x) ((uint)(((ulong)(x) >> 32) & 0xffffffffUL))",
            "",
            f"static const uint sock_filter_policy_{filter_name}_instr_cnt = {instr_cnt};",
            "",
            constructor,
            f"  FD_TEST( out_cnt >= {instr_cnt} );",
            f"  struct sock_filter filter[{instr_cnt}] = {{",
        ],
    )

    for line in prog.render():
        out.write(line)
        out.write("\n")

    write_lines(
        out,
        [
            "  };",
            "  fd_memcpy( out, filter, sizeof( filter ) );",
            "}",
            "",
            "#endif /* defined(__linux__) */",
            "",
            f"#endif /* {guard} */",
        ],
    )


def output_path(src_path: str, filter_name: str) -> str:
    return os.path.join(
        os.path.dirname(src_path), "generated", filter_name + "_seccomp.h"
    )


def main(argv: list[str]) -> None:
    if len(argv) not in (2, 3):
        die(f"usage: {argv[0]} [--stdout] path/to/policy.seccomppolicy")

    to_stdout = False
    src_path = argv[1]
    if len(argv) == 3:
        if src_path != "--stdout":
            die(f"usage: {argv[0]} [--stdout] path/to/policy.seccomppolicy")
        to_stdout = True
        src_path = argv[2]

    filter_name = os.path.basename(src_path)
    if filter_name.endswith(".seccomppolicy"):
        filter_name = filter_name[:-14]

    with open(src_path, "r", encoding="utf-8") as f:
        lines = policy_lines(f.readlines())
    if not lines:
        die("empty policy")

    sigline = lines[0]
    if not (sigline == "noarg" or (" " in sigline and ":" not in sigline)):
        die("malformed signature line")

    entries = []
    for idx, line in enumerate(lines[1:], start=2):
        entries.append((idx, split_policy_line(line, idx)))

    prog = compile_policy(entries, parse_signature(sigline))

    if to_stdout:
        render_header(sys.stdout, src_path, sigline, filter_name, prog)
    else:
        dst = output_path(src_path, filter_name)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as f:
            render_header(f, src_path, sigline, filter_name, prog)


if __name__ == "__main__":
    main(sys.argv)
