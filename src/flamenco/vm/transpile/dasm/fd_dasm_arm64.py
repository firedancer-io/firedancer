# Derived from DynASM (https://luajit.org/dynasm.html).
# Copyright (C) 2005-2026 Mike Pall. All rights reserved.
# Released under the MIT license, see NOTICE.

"""AArch64 backend: operand parser and instruction encoder.

The action list is an array of 32 bit words.  A word whose upper half
is below len(ACTION_NAMES) is an action (number in the upper half,
parameter in the lower half), any other word is an instruction.  Actions
that patch an operand apply to the instruction word right before them
(fd_dasm_arm64.h has the matching enum)."""

import math
import re
from typing import List, Optional, Tuple

from fd_dasm_common import Backend, CType, DasmError, DasmValueError, eval_const, take_parens
from fd_dasm_arm64_ops import CONDITIONS, OPS

# Keep in sync with fd_dasm_arm64.h
ACTION_NAMES = [
    "STOP", "ESC", "ALIGN",
    "REL_LG", "LABEL_LG", "REL_PC", "LABEL_PC",
    "IMM", "IMM6", "IMM12", "IMM13W", "IMM13X", "IMML", "IMMV",
    "VREG",
]  # fmt: skip
ACTION = {name: i for i, name in enumerate(ACTION_NAMES)}

# Label numbers (parameter of REL_LG and LABEL_LG)
#   1..9    local label, forward reference
#   11..19  local label, definition or backward reference
#   20..    global label
LOCAL_BKWD = 10

SHIFTS = {"lsl": 0, "lsr": 1, "asr": 2}
EXTENDS = {"uxtb": 0, "uxth": 1, "uxtw": 2, "uxtx": 3, "sxtb": 4, "sxth": 5, "sxtw": 6, "sxtx": 7}
BTI_TARGETS = {"c": 0x40, "j": 0x80, "jc": 0xC0}
NAMED_REGS = {"xzr": ("x", 31), "wzr": ("w", 31), "lr": ("x", 30)}

_RE_REG = re.compile(r"([xwqdshb])([123]?[0-9])")
_RE_VREG = re.compile(r"R([xwqdshb])(\(.*\))", re.S)
_RE_MEM = re.compile(r"\[\s*(.*?)\s*\](!?)", re.S)
_RE_TYPE_FIELD = re.compile(r"(\w+)\s*(.+)", re.S | re.ASCII)
_RE_BASE_TAIL = re.compile(r"([^,\s]*)\s*(.*)", re.S)
_RE_INDEX = re.compile(r",\s*([^,\s]*)\s*,?\s*(\S*)\s*(.*)", re.S)


def logical_imm(n: int) -> Optional[int]:
    """Returns the N:immr:imms encoding of 64 bit pattern n as a logical
    (bitmask) immediate, or None if n is not encodable.  A 32 bit
    immediate is passed as its pattern repeated twice."""
    mask = (1 << 64) - 1
    lsb = lambda x: x & -x
    inv = False
    if n & 1:
        n, inv = ~n & mask, True
    # n is now 0...01...10...0 repeated: a is the lowest set bit, b the
    # lowest clear bit above it, c the lowest set bit of the next repeat
    a = lsb(n)
    b = lsb((n + a) & mask)
    c = lsb((n + a - b) & mask)
    xa, xb = a.bit_length() - 1, b.bit_length() - 1
    w, s, rep = 64, 0xFFF, 1
    if c:
        w = c.bit_length() - 1 - xa
        if w not in (2, 4, 8, 16, 32):
            return None
        rep = mask // ((1 << w) - 1)
        s = (-2 * w & 0x3F) - 1
    elif not a:
        return None
    elif xb == -1:
        xb = 64
    if ((b - a) * rep) & mask != n:
        return None
    if inv:
        return ((w - xb) << 6) | (s + w + xa - xb)
    return ((w - xa) << 6) | (s + xb - xa)


def _imm_text(text: str) -> str:
    if not text.startswith("#"):
        raise DasmError("expected immediate operand")
    return text[1:]


class Arm64Backend(Backend):
    ARCH = "arm64"
    GLOBAL0 = 20
    GLOBAL_MAX = 2047
    DATA_DIRECTIVES = (".long", ".quad")

    def __init__(self, emit_put):
        super().__init__(emit_put)
        # Type (x w d s q h b) of the registers seen since the last type
        # check of the instruction being parsed
        self.reg_type: Optional[str] = None
        self.sp_ok = False

    # -----------------------------------------------------------------------
    # Action list output

    def put_word(self, n: int) -> None:
        """Appends an instruction or data word."""
        assert 0 <= n <= 0xFFFFFFFF, "word out of range"
        if n >> 16 < len(ACTION_NAMES):
            self.actions.append(ACTION["ESC"] << 16)
        self.actions.append(n)

    def put_action(self, name: str, val: int = 0, arg: Optional[str] = None, npos: int = 0) -> None:
        assert 0 <= val <= 0xFFFF
        self.actions.append((ACTION[name] << 16) + val)
        if arg is not None:
            self.args.append(arg)
            npos = npos or 1
        self.pos += npos

    # -----------------------------------------------------------------------
    # Operand parsers.  Each returns the bits to add to the instruction
    # word; run time operands return 0 and emit an action instead.

    def set_reg_type(self, rt: str) -> None:
        if self.reg_type is None:
            self.reg_type = rt
        elif self.reg_type != rt:
            raise DasmError("register size mismatch")

    def parse_reg(self, expr: Optional[str], shift: int) -> Tuple[int, Optional[CType]]:
        if expr is None:
            raise DasmError("expected register name")
        sp_ok, self.sp_ok = self.sp_ok, False
        tp = self.types.get(expr)
        if tp:
            if tp.reg is None:
                raise DasmError(f"type `{expr}' has no register")
            expr = tp.reg

        if expr == "sp" and sp_ok:
            self.set_reg_type("x")
            return 31 << shift, tp
        if expr in NAMED_REGS:
            rt, r = NAMED_REGS[expr]
            self.set_reg_type(rt)
            return r << shift, tp
        m = _RE_REG.fullmatch(expr)
        if m:
            rt, r = m[1], int(m[2])
            # x31/w31 would be ambiguous between zero register and sp
            if r <= 30 or (r == 31 and rt not in "xw"):
                self.set_reg_type(rt)
                return r << shift, tp
        m = _RE_VREG.fullmatch(expr)
        if m and take_parens(m[2]) == (m[2], ""):
            self.set_reg_type(m[1])
            self.put_action("VREG", shift, m[2])
            return 0, tp
        raise DasmError(f"bad register name `{expr}'")

    def parse_base(self, expr: str) -> Tuple[int, Optional[CType]]:
        """Parses the base register of a memory operand."""
        if expr == "sp":
            return 31 << 5, None
        base, tp = self.parse_reg(expr, 5)
        if self.reg_type != "x":
            raise DasmError("bad register type")
        self.reg_type = None
        return base, tp

    def reg_type_of(self, expr: str) -> str:
        """Returns the type of register operand expr without emitting it."""
        saved = len(self.actions), len(self.args), self.pos
        self.reg_type = None
        self.parse_reg(expr, 0)
        del self.actions[saved[0] :]
        del self.args[saved[1] :]
        self.pos = saved[2]
        return self.reg_type

    def parse_imm(self, text: str, bits: int, shift: int, scale: int, signed: bool) -> int:
        """Immediate of the given bit width at bit `shift`, stored
        divided by 2**scale."""
        imm = _imm_text(text)
        n = eval_const(imm)
        if n is None:
            self.put_action("IMM", (32768 if signed else 0) + scale * 1024 + bits * 32 + shift, imm)
            return 0
        m = n >> scale
        if m << scale == n:
            if signed and -(1 << (bits - 1)) <= m < (1 << (bits - 1)):
                return (m & ((1 << bits) - 1)) << shift
            if not signed and 0 <= m < (1 << bits):
                return m << shift
        raise DasmValueError(f"out of range immediate `{imm}'")

    def parse_imm12(self, text: str) -> int:
        imm = _imm_text(text)
        n = eval_const(imm)
        if n is None:
            self.put_action("IMM12", 0, imm)
            return 0
        if 0 <= n < 0x1000:
            return n << 10
        if 0 <= n < 0x1000000 and n & 0xFFF == 0:
            return (n >> 2) + 0x00400000  # shifted left by 12
        raise DasmValueError(f"out of range immediate `{imm}'")

    def parse_imm13(self, text: str) -> int:
        """Logical immediate.  The register type must be known."""
        imm = _imm_text(text)
        n = eval_const(imm)
        r64 = self.reg_type == "x"
        if n is None:
            if r64:
                self.put_action("IMM13X", 0, f"(unsigned int)({imm})", npos=2)
                self.args.append(f"(unsigned int)((unsigned long long)({imm})>>32)")
            else:
                self.put_action("IMM13W", 0, imm)
            return 0
        bits = 64 if r64 else 32
        if -(1 << (bits - 1)) <= n < (1 << bits):
            n &= (1 << bits) - 1
            enc = logical_imm(n if r64 else n | (n << 32))
            if enc is not None:
                return enc << 10
        raise DasmValueError(f"out of range immediate `{imm}'")

    def parse_imm6(self, text: str) -> int:
        """Bit number of tbz/tbnz."""
        imm = _imm_text(text)
        n = eval_const(imm)
        if n is None:
            self.put_action("IMM6", 0, imm)
            return 0
        if 0 <= n <= 63:
            return ((n & 0x1F) << 19) + (0x80000000 if n >= 32 else 0)
        raise DasmValueError(f"out of range immediate `{imm}'")

    def parse_imm_load(self, imm: str, scale: int) -> int:
        """Offset of a load/store: unsigned 12 bit scaled by the access
        size if possible, else signed 9 bit unscaled."""
        n = eval_const(imm)
        if n is None:
            self.put_action("IMML", scale, imm)
            return 0
        m = n >> scale
        if m << scale == n and 0 <= m < 0x1000:
            return (m << 10) + 0x01000000
        if -256 <= n < 256:
            return (n & 511) << 12
        raise DasmValueError(f"out of range immediate `{imm}'")

    def parse_fpimm(self, text: str) -> int:
        imm = _imm_text(text)
        try:
            n = float(imm)
        except ValueError:
            raise DasmError("floating point immediate must be a constant") from None
        m, e = math.frexp(n)
        s = 0
        if m < 0:
            m, s = -m, 0x00100000
        m = m * 32 - 16
        e2 = (e - 2) & 7
        if m == int(m) and 0 <= m <= 15 and -1 <= e <= 6:
            return s + (e2 << 17) + (int(m) << 13)
        raise DasmValueError(f"out of range immediate `{imm}'")

    def parse_shift(self, expr: str) -> int:
        kind, _, amount = expr.partition(" ")
        if kind not in SHIFTS:
            raise DasmError("expected shift operand")
        return self.parse_imm(amount.strip(), 6, 10, 0, False) + (SHIFTS[kind] << 22)

    def parse_lslx16(self, expr: str) -> int:
        m = re.fullmatch(r"lsl\s*#(\d+)", expr)
        if not m:
            raise DasmError("expected shift operand")
        n = int(m[1])
        if n not in ((0, 16, 32, 48) if self.reg_type == "x" else (0, 16)):
            raise DasmError("bad shift amount")
        return n << 17

    def parse_extend(self, expr: str) -> int:
        kind, _, amount = expr.partition(" ")
        if kind == "lsl":
            s = 3 if self.reg_type == "x" else 2
        elif kind in EXTENDS:
            s = EXTENDS[kind]
        else:
            raise DasmError("expected extend operand")
        amount = amount.strip()
        return (self.parse_imm(amount, 3, 10, 0, False) if amount else 0) + (s << 13)

    def parse_cond(self, expr: str, invert: int) -> int:
        if expr not in CONDITIONS:
            raise DasmError("expected condition operand")
        return (CONDITIONS[expr] ^ invert) << 12

    def parse_load(self, params: List[str], n: int, op: int) -> int:
        """Memory operand of a load/store, starting at params[n]:
        [base], [base, #imm], [base, #imm]!, [base], #imm,
        [base, index {, lsl|uxtw|sxtw|sxtx {#amount}}], or type->field."""
        if len(params) > n + 2:
            raise DasmError("too many operands")
        scale = op >> 30
        pn = params[n]
        p2 = params[n + 1] if len(params) > n + 1 else None
        m = _RE_MEM.fullmatch(pn)
        if not m:
            mt = _RE_TYPE_FIELD.fullmatch(pn) if p2 is None else None
            if mt:
                base, tp = self.parse_base(mt[1])
                if tp:
                    self.put_action("IMML", scale, tp.offset_expr(mt[2]))
                    return op + base
            raise DasmError("expected address operand")
        p1, wb = m[1], m[2]

        if p2 is not None:  # post-index
            if wb:
                raise DasmError("bad use of '!'")
            return op + self.parse_base(p1)[0] + self.parse_imm(p2, 9, 12, 0, True) + 0x400
        if wb:  # pre-index
            base, sep, imm = p1.partition(",")
            if not sep:
                raise DasmError("bad use of '!'")
            return op + self.parse_base(base.strip())[0] + self.parse_imm(imm.strip(), 9, 12, 0, True) + 0xC00

        m = _RE_BASE_TAIL.fullmatch(p1)
        op += self.parse_base(m[1])[0]
        tail = m[2]
        if tail == "":
            return op + 0x01000000
        mi = re.fullmatch(r",\s*#(.*)", tail, re.S)
        if mi:
            return op + self.parse_imm_load(mi[1], scale)

        # Register index
        mi = _RE_INDEX.fullmatch(tail)
        if not mi:
            raise DasmError("expected address operand")
        index, ext, amount = mi[1], mi[2], mi[3]
        op += self.parse_reg(index, 16)[0] + 0x00200800
        if self.reg_type not in ("x", "w"):
            raise DasmError("bad index register type")
        if ext == "":
            if self.reg_type != "x":
                raise DasmError("bad index register type")
            return op + 0x6000
        if amount == f"#{scale}":
            op += 0x1000
        elif amount not in ("", "#0"):
            raise DasmError("bad scale")
        if self.reg_type == "x":
            if ext == "lsl" and amount != "":
                return op + 0x6000
            if ext == "sxtx":
                return op + 0xE000
        else:
            if ext == "uxtw":
                return op + 0x4000
            if ext == "sxtw":
                return op + 0xC000
        raise DasmError("bad extend/shift specifier")

    def parse_load_pair(self, params: List[str], n: int, op: int) -> int:
        """Memory operand of ldp/stp."""
        if len(params) > n + 2:
            raise DasmError("too many operands")
        pn = params[n]
        p2 = params[n + 1] if len(params) > n + 1 else None
        scale = 2 + (op >> (31 - ((op >> 26) & 1)))
        m = _RE_MEM.fullmatch(pn)
        if not m:
            mt = _RE_TYPE_FIELD.fullmatch(pn) if p2 is None else None
            if mt:
                base, tp = self.parse_base(mt[1])
                if tp:
                    self.put_action("IMM", 32768 + 7 * 32 + 15 + scale * 1024, tp.offset_expr(mt[2]))
                    return op + base + 0x01000000
            raise DasmError("expected address operand")
        p1, wb = m[1], m[2]
        if p2 is not None:  # post-index
            if wb:
                raise DasmError("bad use of '!'")
            op += 0x00800000
        else:
            base, sep, imm = p1.partition(",")
            p1, p2 = (base.strip(), imm.strip()) if sep else (p1, "#0")
            op += 0x01800000 if wb else 0x01000000
        return op + self.parse_base(p1)[0] + self.parse_imm(p2, 7, 15, scale, True)

    def put_branch(self, text: str, op: int) -> None:
        """Label operand of a pc relative instruction."""
        if op & 0x7C000000 == 0x14000000:
            kind = 0  # b, bl
        elif op >> 24 == 0x54 or op & 0x7E000000 == 0x34000000 or op & 0x3B000000 == 0x18000000:
            kind = 0x800  # b.cond, cbz, cbnz, ldr literal
        elif op & 0x7E000000 == 0x36000000:
            kind = 0x1000  # tbz, tbnz
        elif op & 0x9F000000 == 0x10000000:
            kind = 0x2000  # adr
        else:
            kind = 0x3000  # adrp
        if text.startswith("=>"):
            self.put_action("REL_PC", kind, text[2:])
        elif text.startswith("->"):
            self.put_action("REL_LG", kind + self.global_label(text[2:]), npos=1)
        else:
            m = re.fullmatch(r"([<>])([1-9])", text)
            if not m:
                raise DasmError(f"bad label `{text}'")
            self.put_action("REL_LG", kind + int(m[2]) + (LOCAL_BKWD if m[1] == "<" else 0), npos=1)

    # -----------------------------------------------------------------------
    # Instruction encoder

    def template(self, op: str, nparams: int) -> Optional[str]:
        return OPS.get(f"{op}_{nparams}") or OPS.get(f"{op}_*")

    def has_instruction(self, op: str, nparams: int) -> bool:
        return self.template(op, nparams) is not None

    def instruction(self, op: str, params: List[str]) -> None:
        template = self.template(op, len(params))
        params = list(params)

        # Aliases of the bitfield move instructions
        if op == "lsl" and params[2].startswith("#"):
            # lsl rd, rn, #sh  ->  ubfm rd, rn, #(-sh mod size), #(size-1-sh)
            sh, size = params[2][1:], 32 if self.reg_type_of(params[0]) == "w" else 64
            params[2] = f"#({size}-({sh}))%{size}"
            params.append(f"#{size-1}-({sh})")
            template = OPS["ubfm_4"]
        elif template.startswith("@bfx:"):
            # xbfx rd, rn, #lsb, #width  ->  xbfm rd, rn, #lsb, #(lsb+width-1)
            params[3] = f"#({params[2][1:]})+({params[3][1:]})-1"
            template = OPS[template[5:]]
        elif template.startswith("@bfiz:"):
            # xbfiz rd, rn, #lsb, #width  ->  xbfm rd, rn, #(-lsb mod size), #(width-1)
            size = 32 if self.reg_type_of(params[0]) == "w" else 64
            params[2] = f"#({size}-({params[2][1:]}))%{size}"
            params[3] = f"#({params[3][1:]})-1"
            template = OPS[template[6:]]

        self.reserve(4)  # an instruction has at most 4 run time operands
        saved = len(self.actions), len(self.args), self.pos
        # If no alternative accepts the operands, report the most specific
        # reason: a bad value over a mismatched operand kind
        err: Optional[DasmError] = None
        for alt in template.split("|"):
            try:
                return self.encode(alt, params)
            except DasmError as e:
                if not isinstance(err, DasmValueError):
                    err = e
                del self.actions[saved[0] :]
                del self.args[saved[1] :]
                self.pos = saved[2]
        raise err

    def encode(self, alt: str, params: List[str]) -> None:
        """Encodes one instruction following a template alternative (see
        fd_dasm_arm64_ops.py for the template characters)."""
        op = int(alt[:8], 16)
        start = len(self.actions)
        self.actions.append(0)  # placeholder, the operand actions follow the instruction word
        self.reg_type = None
        self.sp_ok = False
        n = 0

        def take() -> str:
            nonlocal n
            if n >= len(params):
                raise DasmError("too few operands")
            n += 1
            return params[n - 1]

        for c in alt[8:]:
            if c in "DNMA":
                op += self.parse_reg(take(), {"D": 0, "N": 5, "M": 16, "A": 10}[c])[0]
            elif c == "m":
                op += self.parse_reg(params[n - 1], 16)[0]
            elif c == "p":
                self.sp_ok = True
            elif c == "g":
                if self.reg_type == "x":
                    op += 0x80000000
                elif self.reg_type != "w":
                    raise DasmError("bad register type")
                self.reg_type = None
            elif c == "f":
                if self.reg_type == "d":
                    op += 0x00400000
                elif self.reg_type != "s":
                    raise DasmError("bad register type")
                self.reg_type = None
            elif c in "xwdsq":
                if self.reg_type != c:
                    raise DasmError("register size mismatch")
                self.reg_type = None
            elif c == "L":
                op = self.parse_load(params, n, op)
                n = len(params)
            elif c == "P":
                op = self.parse_load_pair(params, n, op)
                n = len(params)
            elif c == "B":
                self.put_branch(take(), op)
            elif c == "I":
                op += self.parse_imm12(take())
            elif c == "i":
                op += self.parse_imm13(take())
            elif c == "W":
                op += self.parse_imm(take(), 16, 5, 0, False)
            elif c == "T":
                op += self.parse_imm6(take())
            elif c == "1":
                op += self.parse_imm(take(), 6, 16, 0, False)
            elif c == "2":
                op += self.parse_imm(take(), 6, 10, 0, False)
            elif c == "5":
                op += self.parse_imm(take(), 5, 16, 0, False)
            elif c == "V":
                op += self.parse_imm(take(), 4, 0, 0, False)
            elif c == "F":
                op += self.parse_fpimm(take())
            elif c == "Z":
                if take() not in ("#0", "#0.0"):
                    raise DasmError("expected zero immediate")
            elif c == "S":
                op += self.parse_shift(take())
            elif c == "X":
                op += self.parse_extend(take())
            elif c == "R":
                op += self.parse_lslx16(take())
            elif c == "C":
                op += self.parse_cond(take(), 0)
            elif c == "c":
                op += self.parse_cond(take(), 1)
            elif c == "t":
                target = take()
                if target not in BTI_TARGETS:
                    raise DasmError("bad operand")
                op += BTI_TARGETS[target]
            else:
                raise AssertionError(f"bad template char `{c}'")
        if n != len(params):
            raise DasmError("too many operands")

        operand_actions = self.actions[start + 1 :]
        del self.actions[start:]
        self.put_word(op)
        self.actions += operand_actions

    # -----------------------------------------------------------------------
    # Directives

    def label(self, text: str) -> None:
        self.reserve(1)
        if re.fullmatch(r"[1-9]", text):
            self.put_action("LABEL_LG", LOCAL_BKWD + int(text), npos=1)
        elif text.startswith("->"):
            self.put_action("LABEL_LG", self.global_label(text[2:]), npos=1)
        elif text.startswith("=>"):
            self.put_action("LABEL_PC", 0, text[2:])
        else:
            raise DasmError("bad label definition")

    def data(self, op: str, params: List[str]) -> None:
        for p in params:
            n = eval_const(p)
            if op == ".long":
                if n is None:
                    self.put_action("IMMV", 0, p)
                elif -(1 << 31) <= n < (1 << 32):
                    self.put_word(n & 0xFFFFFFFF)
                else:
                    raise DasmError(f"bad immediate `{p}'")
            elif n is None:
                self.put_action("IMMV", 0, f"(unsigned int)({p})")
                self.put_action("IMMV", 0, f"(unsigned int)((unsigned long long)({p})>>32)")
            elif -(1 << 63) <= n < (1 << 64):
                self.put_word(n & 0xFFFFFFFF)
                self.put_word((n >> 32) & 0xFFFFFFFF)
            else:
                raise DasmError(f"bad immediate `{p}'")
            self.reserve(2)

    def align(self, text: str) -> None:
        self.reserve(1)
        n = eval_const(text)
        if n not in (4, 8, 16, 32, 64, 128, 256):
            raise DasmError("bad alignment")
        self.put_action("ALIGN", n - 1, npos=1)

    def terminate(self) -> None:
        self.put_action("STOP")

    def format_actions(self, name: str) -> str:
        actions = self.actions or [ACTION["STOP"] << 16]
        lines = [f"static uint const {name}[ {len(actions)} ] = {{"]
        for i in range(0, len(actions), 6):
            lines.append("  " + ",".join(f"0x{w:08x}" for w in actions[i : i + 6]) + ",")
        lines[-1] = lines[-1].rstrip(",")
        lines.append("};")
        return "\n".join(lines)
