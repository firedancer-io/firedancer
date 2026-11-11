# Derived from DynASM (https://luajit.org/dynasm.html).
# Copyright (C) 2005-2026 Mike Pall. All rights reserved.
# Released under the MIT license, see NOTICE.

"""Pieces shared by the fd_dasm front end and its architecture backends:
error type, C operand text helpers, and the Backend base class."""

import ast
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple


# Keep in sync with FD_DASM_VERSION
DASM_VERSION = 1


class DasmError(Exception):
    """An error in the input file.  The front end adds file and line."""


class DasmValueError(DasmError):
    """An operand of the right kind with a value that cannot be encoded."""


# ---------------------------------------------------------------------------
# Operand text helpers
#
# Operands are either constants the generator can fold into the action
# list, or opaque C expressions that are passed to fd_dasm_put at run
# time.  Only the constant forms below are ever interpreted; everything
# else is copied to the output verbatim and evaluated by the C compiler.

_RE_INT = re.compile(r"([+-]?)(0[xX][0-9a-fA-F]+|[0-9]+)")
_RE_CONST = re.compile(r"(?:\s+|0[xX][0-9a-fA-F]+|[0-9]+|[-+*%()])+")
_BRACKETS = {"(": ")", "[": "]", "{": "}"}


def parse_int(text: str) -> Optional[int]:
    """Returns the value of a decimal or hex integer literal, or None if
    text is anything else."""
    m = _RE_INT.fullmatch(text.strip())
    if not m:
        return None
    digits = m[2]
    if len(digits) > 1 and digits[0] == "0" and digits[1] not in "xX":
        raise DasmError(f"octal literal `{text.strip()}' is ambiguous, use decimal or hex")
    value = int(digits, 0)
    return -value if m[1] == "-" else value


def eval_const(text: str) -> Optional[int]:
    """Folds integer arithmetic over literals (+ - * % and parentheses).
    Returns None if text is not such an expression.  The result always
    agrees with what a C compiler would compute."""
    if not _RE_CONST.fullmatch(text):
        return None
    try:
        tree = ast.parse(text.strip(), mode="eval")
    except SyntaxError:
        return None
    return _fold(tree.body)


def _fold(node: ast.AST) -> Optional[int]:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        v = _fold(node.operand)
        if v is None:
            return None
        return -v if isinstance(node.op, ast.USub) else v
    if isinstance(node, ast.BinOp):
        a, b = _fold(node.left), _fold(node.right)
        if a is None or b is None:
            return None
        if isinstance(node.op, ast.Add):
            return a + b
        if isinstance(node.op, ast.Sub):
            return a - b
        if isinstance(node.op, ast.Mult):
            return a * b
        # C and Python disagree on % for negative operands
        if isinstance(node.op, ast.Mod) and a >= 0 and b > 0:
            return a % b
    return None


def take_parens(text: str) -> Optional[Tuple[str, str]]:
    """Splits "(a(b))rest" into ("(a(b))", "rest").  Returns None if text
    does not start with a balanced parenthesized group."""
    if not text.startswith("("):
        return None
    depth = 0
    for i, c in enumerate(text):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[: i + 1], text[i + 1 :]
    return None


def split_statement(stmt: str) -> Tuple[str, List[str]]:
    """Splits "op a, b(c, d), [e, f]" into ("op", ["a", "b(c, d)", "[e, f]"]).
    A comma directly after the op is optional."""
    stmt = stmt.strip()
    m = re.match(r"[^\s,]+", stmt)
    if not m:
        raise DasmError("bad statement syntax")
    op = m[0]
    rest = stmt[m.end() :].lstrip()
    if rest.startswith(","):
        rest = rest[1:]
    if not rest.strip():
        return op, []

    params: List[str] = []
    closers: List[str] = []
    start = 0
    for i, c in enumerate(rest):
        if c in _BRACKETS:
            closers.append(_BRACKETS[c])
        elif c in ")]}":
            if not closers or closers.pop() != c:
                raise DasmError("unbalanced (), [] or {}")
        elif c == "," and not closers:
            params.append(rest[start:i].strip())
            start = i + 1
    if closers:
        raise DasmError("unbalanced (), [] or {}")
    params.append(rest[start:].strip())
    if "" in params:
        raise DasmError("empty operand")
    return op, params


# ---------------------------------------------------------------------------


@dataclass
class CType:
    """A `.type name, ctype [, reg]` declaration.  `name->field` operands
    become memory operands at offsetof(ctype, field) from reg."""

    ctype: str
    reg: Optional[str]
    index: int

    def offset_expr(self, accessor: str) -> str:
        return f"Dt{self.index:X}({accessor})"


class Backend:
    """Assembles statements into the action list.

    The action list is the constant part of the machine code interleaved
    with action codes for everything only known at run time.  Statements
    accumulate until flush(), which closes the pending chunk and emits
    one fd_dasm_put call replaying it with the collected C arguments."""

    ARCH: str
    PUT_POS_MAX = 25  # keep in sync with FD_DASM_PUT_POS_MAX
    GLOBAL0: int  # label number of the first global label
    GLOBAL_MAX: int
    ACTION_CTYPE: str
    DATA_DIRECTIVES: Tuple[str, ...]

    def __init__(self, emit_put: Callable[[int, List[str]], None]):
        self.emit_put = emit_put
        self.actions: List[int] = []
        self.put_ofs = 0  # action list offset of the pending chunk
        self.args: List[str] = []  # C arguments of the pending chunk
        self.pos = 1  # buffer positions the pending chunk uses at run time
        self.globals: Dict[str, int] = {}
        self.types: Dict[str, CType] = {}

    # Interface implemented by each architecture

    def instruction(self, op: str, params: List[str]) -> None:
        raise NotImplementedError

    def has_instruction(self, op: str, nparams: int) -> bool:
        raise NotImplementedError

    def label(self, text: str) -> None:
        raise NotImplementedError

    def data(self, op: str, params: List[str]) -> None:
        raise NotImplementedError

    def align(self, text: str) -> None:
        raise NotImplementedError

    def check_type_reg(self, reg: str) -> None:
        pass

    def terminate(self) -> None:
        """Appends the STOP action."""
        raise NotImplementedError

    def dedupe(self) -> int:
        """Returns the action list offset to use for the pending chunk."""
        return self.put_ofs

    def format_actions(self, name: str) -> str:
        raise NotImplementedError

    # Shared implementation

    def reserve(self, npos: int) -> None:
        """Starts a new chunk if the pending one cannot take npos more
        buffer positions."""
        if self.pos + npos > self.PUT_POS_MAX:
            self.flush()

    def flush(self) -> None:
        if len(self.actions) == self.put_ofs:
            return
        self.terminate()
        self.emit_put(self.dedupe(), self.args)
        self.put_ofs = len(self.actions)
        self.args = []
        self.pos = 1

    def global_label(self, name: str) -> int:
        n = self.globals.get(name)
        if n is None:
            if not re.fullmatch(r"[A-Za-z_]\w*", name, re.ASCII):
                raise DasmError(f"bad global label `{name}'")
            n = self.GLOBAL0 + len(self.globals)
            if n > self.GLOBAL_MAX:
                raise DasmError("too many global labels")
            self.globals[name] = n
        return n

    def define_type(self, name: str, ctype: str, reg: Optional[str]) -> str:
        """Returns the C line defining the type's offset macro."""
        if not re.fullmatch(r"[A-Za-z_]\w*", name, re.ASCII):
            raise DasmError(f"bad type name `{name}'")
        if name in self.types:
            raise DasmError(f"duplicate type `{name}'")
        if reg is not None:
            self.check_type_reg(reg)
        tp = CType(ctype, reg, len(self.types) + 1)
        self.types[name] = tp
        return f"#define Dt{tp.index:X}(_V) (int)(ptrdiff_t)&((({ctype} *)0)_V)"
