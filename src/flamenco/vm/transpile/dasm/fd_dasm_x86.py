# Derived from DynASM (https://luajit.org/dynasm.html).
# Copyright (C) 2005-2026 Mike Pall. All rights reserved.
# Released under the MIT license, see NOTICE.

"""x86-64 backend: operand parser and instruction encoder.

The action list is a byte string.  Bytes below ACTION0 are machine code,
bytes from ACTION0 up are actions (fd_dasm_x86.h has the matching enum
and documents what each action does at run time)."""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union

from fd_dasm_common import Backend, DasmError, parse_int, take_parens
from fd_dasm_x86_ops import OPS

# Keep in sync with fd_dasm_x86.h
ACTION_NAMES = [
    # one int argument, one buffer position
    "DISP", "IMM_S", "IMM_B", "IMM_W", "IMM_D", "IMM_WB", "IMM_DB",
    # one action byte, one int argument, one buffer position
    "VREG",
    # one action byte (REL_LG) or one int argument (REL_PC), two buffer positions
    "REL_LG", "REL_PC",
    # one action byte (LABEL_LG) or one int argument (LABEL_PC), one buffer position
    "LABEL_LG", "LABEL_PC",
    # one action byte, one buffer position
    "ALIGN",
    # one action byte
    "ESC",
    # nothing
    "MARK", "STOP",
]  # fmt: skip
ACTION0 = 256 - len(ACTION_NAMES)
ACTION = {name: ACTION0 + i for i, name in enumerate(ACTION_NAMES)}

# Label numbers (the action byte of REL_LG and LABEL_LG)
#   1..9      local label, backward reference
#   10..246   global label
#   247..255  local label, forward reference
LOCAL_FWD = 246

# Where a run time register number is patched into the instruction.  The
# VREG action byte is this kind, plus the distance back to the REX/VEX
# prefix in the low 3 bits, plus 8 for each earlier VREG of the same
# instruction that may ask to drop the prefix.
VREG_KIND = {
    "modrm.rm.m": 0x00,
    "modrm.rm.r": 0x20,
    "opcode": 0x20,
    "sib.base": 0x20,
    "sib.index": 0x40,
    "modrm.reg": 0x80,
    "vex.v": 0xA0,
    "imm.hi": 0xC0,
}

OPSIZE_NAMES = {"byte": "b", "word": "w", "dword": "d", "qword": "q", "oword": "o", "yword": "y", "tword": "t", "aword": "q"}
OPSIZE_BYTES = {"b": 1, "w": 2, "d": 4, "q": 8, "o": 16, "y": 32, "t": 10}
DATA_SIZES = {".byte": "b", ".sbyte": "s", ".word": "w", ".dword": "d", ".long": "d", ".qword": "q", ".quad": "q"}

_RE_OPSIZE = re.compile(r"(" + "|".join(OPSIZE_NAMES) + r")\b\s*(.+)", re.S)
_RE_WORD = re.compile(r"(\w+)\s*(.*)", re.S | re.ASCII)
_RE_SCALE = re.compile(r"\*\s*([1248])\s*(.*)", re.S)
_RE_PLUS_WORD = re.compile(r"\+\s*(\w+)\s*(.*)", re.S | re.ASCII)
_RE_SIGNED = re.compile(r"([+-])\s*(.+)", re.S)
_RE_LOCAL_REF = re.compile(r"([<>])([1-9])")


@dataclass(frozen=True)
class Reg:
    size: str  # b w d q, f (x87), o (xmm), y (ymm)
    num: int  # -1 if the register number is a run time value
    needrex: Optional[bool] = None  # byte registers: True needs REX, False forbids it


def _build_regs() -> Dict[str, Reg]:
    regs: Dict[str, Reg] = {}
    legacy = {
        "q": "rax rcx rdx rbx rsp rbp rsi rdi",
        "d": "eax ecx edx ebx esp ebp esi edi",
        "w": "ax cx dx bx sp bp si di",
        "b": "al cl dl bl ah ch dh bh",
    }
    for size, names in legacy.items():
        for i, name in enumerate(names.split()):
            regs[name] = Reg(size, i, False if size == "b" and i >= 4 else None)
        suffix = "" if size == "q" else size
        for i in range(16):
            regs[f"r{i}{suffix}"] = Reg(size, i, True if size == "b" and i >= 4 else None)
    for i in range(8):
        regs[f"st{i}"] = Reg("f", i)
    for i in range(16):
        regs[f"xmm{i}"] = Reg("o", i)
        regs[f"ymm{i}"] = Reg("y", i)
    # Rq(expr) etc: register number is the C expression
    regs.update(Rq=Reg("q", -1), Rd=Reg("d", -1), Rw=Reg("w", -1), Rb=Reg("b", -1, True))
    regs.update(Ra=Reg("q", -1), Rf=Reg("f", -1), xmm=Reg("o", -1), ymm=Reg("y", -1))
    return regs


REGS = _build_regs()


def _addressable(reg: Reg) -> bool:
    return reg.size in "qd"


def _valid_index(reg: Reg) -> bool:
    return _addressable(reg) and reg.num != 4


@dataclass
class Label:
    num: Optional[int] = None  # local or global label number
    pc: Optional[str] = None  # C expression giving a pc label index


Imm = Union[int, str, Label]  # str is a C expression evaluated at run time


@dataclass
class Operand:
    # Each character of mode is a property the templates can match on,
    # see fd_dasm_x86_ops.py
    mode: str = ""
    opsize: Optional[str] = None
    needrex: Optional[bool] = None
    # Register, or base register of a memory operand
    reg: Optional[int] = None
    vreg: Optional[str] = None  # C expression if reg==-1
    # Index register of a memory operand
    xreg: Optional[int] = None
    vxreg: Optional[str] = None
    xsc: Optional[int] = None  # log2 of the index scale
    disp: Optional[Imm] = None
    imm: Optional[Imm] = None


@dataclass
class Vex:
    m: int  # opcode map: 1=0F 2=0F38 3=0F3A
    p: int  # mandatory prefix: 0=none 1=66 2=F3 3=F2
    v: Optional[Operand]
    l: bool = False


class X86Backend(Backend):
    ARCH = "x64"
    GLOBAL0 = 10
    GLOBAL_MAX = LOCAL_FWD
    DATA_DIRECTIVES = tuple(DATA_SIZES)

    def __init__(self, emit_put):
        super().__init__(emit_put)
        self.vreg_shrink_count = 0

    # -----------------------------------------------------------------------
    # Action list output

    def put_raw(self, n: int) -> None:
        assert 0 <= n <= 255, "byte out of range"
        self.actions.append(n)

    def put_byte(self, n: int) -> None:
        """Appends a machine code byte."""
        if n >= ACTION0:
            self.put_raw(ACTION["ESC"])
        self.put_raw(n)

    def put_action(self, name: str, arg: Optional[str] = None, npos: int = 0) -> None:
        self.put_raw(ACTION[name])
        if arg is not None:
            self.args.append(arg)
            npos = npos or 1
        self.pos += npos

    def put_vreg(self, kind: str, vreg: Optional[str], psz: int = 0, sk: int = 0, defer: bool = False) -> None:
        """Patches a run time register number into the previous byte.

        psz is the distance from here back to the REX/VEX prefix.  VREGs
        with a kind below sk can use a shorter prefix when the register
        number is below 8; the count of those accumulates over deferred
        VREGs and is stored with the last VREG of the instruction."""
        if vreg is None:
            return
        self.put_action("VREG", vreg)
        b = VREG_KIND[kind]
        if b < sk:
            self.vreg_shrink_count += 1
        if not defer:
            b += self.vreg_shrink_count * 8
            self.vreg_shrink_count = 0
        self.put_raw(b + psz)

    def put_rel(self, label: Label) -> None:
        if label.pc is not None:
            self.put_action("REL_PC", label.pc, 2)
        else:
            self.put_action("REL_LG", npos=2)
            self.put_raw(label.num)

    def put_imm8s(self, n: Imm) -> None:
        if isinstance(n, int):
            if not -128 <= n <= 127:
                raise DasmError("signed immediate byte out of range")
            self.put_byte(n & 255)
        else:
            self.put_action("IMM_S", _expr(n))

    def put_imm8(self, n: Imm) -> None:
        if isinstance(n, int):
            if not 0 <= n <= 255:
                raise DasmError("unsigned immediate byte out of range")
            self.put_byte(n)
        else:
            self.put_action("IMM_B", _expr(n))

    def put_imm16(self, n: Imm) -> None:
        if isinstance(n, int):
            if not 0 <= n <= 0xFFFF:
                raise DasmError("unsigned immediate word out of range")
            self.put_byte(n & 255)
            self.put_byte(n >> 8)
        else:
            self.put_action("IMM_W", _expr(n))

    def put_imm32(self, n: Imm) -> None:
        if isinstance(n, int):
            for shift in (0, 8, 16, 24):
                self.put_byte((n >> shift) & 255)
        else:
            self.put_action("IMM_D", _expr(n))

    def put_imm64(self, n: Imm) -> None:
        if isinstance(n, int):
            for shift in range(0, 64, 8):
                self.put_byte((n >> shift) & 255)
        else:
            self.put_action("IMM_D", f"(unsigned int)({_expr(n)})")
            self.put_action("IMM_D", f"(unsigned int)((unsigned long long)({_expr(n)})>>32)")

    def put_imm_sized(self, sz: Optional[str], n: Imm) -> None:
        if sz in (None, "d", "q"):
            self.put_imm32(n)
        elif sz == "w":
            self.put_imm16(n)
        elif sz == "b":
            self.put_imm8(n)
        elif sz == "s":
            self.put_imm8s(n)
        else:
            raise DasmError("bad operand size")

    def put_opcode(
        self, sz: Optional[str], op: int, rex: int, vex: Optional[Vex] = None, vregr: bool = False, vregxb: bool = False
    ) -> Tuple[int, int]:
        """Emits prefixes and opcode bytes.  rex bits: 1=B 2=X 4=R 8=W,
        16=a REX prefix is required even if no bit is set.  vregr/vregxb
        tell whether ModRM.reg / rm,base,index are run time registers.

        Returns (psz, sk) for the VREG actions of this instruction."""
        psz, sk = 0, 0
        if vex:
            tail = None
            if vex.m == 1 and (rex & 11) == 0:
                if vregxb:
                    sk = VREG_KIND["modrm.reg"]  # run time picks 2 or 3 byte VEX
                else:
                    self.put_byte(0xC5)
                    tail = ((rex & 4) ^ 4) << 5
                    psz = 3
            if tail is None:
                self.put_byte(0xC4)
                self.put_byte((((rex & 7) ^ 7) << 5) + vex.m)
                tail = (rex & 8) << 4
                psz = 4
            reg, vreg = 0, None
            if vex.v:
                if vex.v.reg is None:
                    raise DasmError("bad vex operand")
                reg = vex.v.reg
                if reg < 0:
                    reg, vreg = 0, vex.v.vreg
            if sz == "y" or vex.l:
                tail += 4
            self.put_byte(tail + ((reg ^ 15) << 3) + vex.p)
            self.put_vreg("vex.v", vreg)
            rex = 0
            if op >= 256:
                raise DasmError("bad vex opcode")
        elif rex == 0 and (vregr or vregxb):
            rex = 0x10
            sk = VREG_KIND["vex.v"]  # run time drops the REX prefix if unused

        if sz == "w":
            self.put_byte(0x66)
        if op >= 1 << 32:
            self.put_byte(op >> 32)
            op &= 0xFFFFFFFF
        if op >= 1 << 24:
            self.put_byte(op >> 24)
            op &= 0xFFFFFF
        if op >= 1 << 16:
            if rex and (op & 0xFFFF00) in (0x0F3A00, 0x0F3800):
                self.put_byte(0x40 + (rex & 15))
                rex = 0
                psz = 2
            self.put_byte(op >> 16)
            op &= 0xFFFF
            psz += 1
        if op >= 256:
            b = op >> 8
            if b == 0x0F and rex:
                self.put_byte(0x40 + (rex & 15))
                rex = 0
                psz = 2
            self.put_byte(b)
            op &= 255
            psz += 1
        if rex:
            self.put_byte(0x40 + (rex & 15))
            psz = 2
        if sz == "b":
            op -= 1
        self.put_byte(op)
        return psz, sk

    def put_modrm(self, mod: int, reg: int, rm: int) -> None:
        """Appends a ModRM byte (or a SIB byte, which has the same shape)."""
        self.put_byte((mod << 6) + ((reg & 7) << 3) + (rm & 7))

    def put_modrm_sib(self, t: Operand, imark: str, s: int, vsreg: Optional[str], psz: int, sk: int) -> None:
        """Emits ModRM, SIB and displacement for operand t.  s is the
        ModRM.reg field, vsreg its C expression if known only at run
        time.  imark is the last pattern character."""
        reg, vreg = t.reg, None
        xreg, vxreg = t.xreg, None
        if reg is not None and reg < 0:
            reg, vreg = 0, t.vreg
        if xreg is not None and xreg < 0:
            xreg, vxreg = 0, t.vxreg
        s = max(s, 0)

        if t.mode.startswith("r"):
            self.put_modrm(3, s, reg)
            self.put_vreg("modrm.reg", vsreg, psz + 1, sk, defer=vreg is not None)
            self.put_vreg("modrm.rm.r", vreg, psz + 1, sk)
            return

        disp = t.disp
        if reg is None:
            if xreg is not None:
                # [xreg*xsc+disp] is SIB with base=101b, mod=00b
                self.put_modrm(0, s, 4)
                if imark == "I":
                    self.put_action("MARK")
                self.put_vreg("modrm.reg", vsreg, psz + 1, sk, defer=vxreg is not None)
                self.put_modrm(t.xsc, xreg, 5)
                self.put_vreg("sib.index", vxreg, psz + 2, sk)
            elif not isinstance(disp, Label):
                # [disp32] is SIB with base=101b, index=100b, mod=00b
                self.put_modrm(0, s, 4)
                self.put_vreg("modrm.reg", vsreg, psz + 1, sk)
                if imark == "I":
                    self.put_action("MARK")
                self.put_modrm(0, 4, 5)
            else:
                # [label] is rip relative
                self.put_modrm(0, s, 5)
                self.put_vreg("modrm.reg", vsreg, psz + 1, sk)
                if imark in "UWSiI":
                    raise DasmError("rip-relative displacement followed by an immediate is not supported")
                self.put_rel(disp)
                return
            self.put_imm32(disp)
            return

        if isinstance(disp, Label):
            raise DasmError("label displacement with a base register")

        # mod: 0=no displacement 1=disp8 2=disp32, None=decided at run time
        mod: Optional[int] = None
        if isinstance(disp, int):
            if disp == 0 and (reg & 7) != 5:
                if vreg is None:  # a run time base might be rbp/r13, which need a displacement
                    mod = 0
            elif -128 <= disp <= 127:
                mod = 1
            else:
                mod = 2

        if xreg is not None or (reg & 7) == 4:
            self.put_modrm(2 if mod is None else mod, s, 4)
            if mod is None or imark == "I":
                self.put_action("MARK")
            self.put_vreg("modrm.reg", vsreg, psz + 1, sk, defer=vxreg is not None or vreg is not None)
            self.put_modrm(t.xsc or 0, 4 if xreg is None else xreg, reg)
            self.put_vreg("sib.index", vxreg, psz + 2, sk, defer=vreg is not None)
            self.put_vreg("sib.base", vreg, psz + 2, sk)
        else:
            self.put_modrm(2 if mod is None else mod, s, reg)
            if (imark == "I" and mod in (1, 2)) or (mod is None and (vsreg is not None or vreg is not None)):
                self.put_action("MARK")
            self.put_vreg("modrm.reg", vsreg, psz + 1, sk, defer=vreg is not None)
            self.put_vreg("modrm.rm.m", vreg, psz + 1, sk)

        if mod == 1:
            self.put_imm8s(disp)
        elif mod == 2:
            self.put_imm32(disp)
        elif mod is None:
            self.put_action("DISP", _expr(disp))

    # -----------------------------------------------------------------------
    # Operand parser

    def parse_imm(self, expr: str) -> Tuple[str, Imm]:
        """Returns (mode, value) of an immediate or label operand."""
        if expr.startswith("=>"):
            return "iJ", Label(pc=expr[2:])
        if expr.startswith("->"):
            return "iJ", Label(num=self.global_label(expr[2:]))
        m = _RE_LOCAL_REF.fullmatch(expr)
        if m:
            return "iJ", Label(num=int(m[2]) + (LOCAL_FWD if m[1] == ">" else 0))
        if expr.startswith("&") or expr.startswith("extern "):
            raise DasmError(f"unsupported operand `{expr}'")
        return "iI", expr

    def parse_disp(self, expr: str) -> Imm:
        """Parses the "+-disp" tail of a memory operand."""
        if expr == "":
            return 0
        n = _parse_imm32(expr)
        if n is not None:
            return n
        m = _RE_SIGNED.fullmatch(expr)
        if not m:
            raise DasmError(f"bad displacement expression `{expr}'")
        sign, tail = m[1], m[2]
        mode, value = self.parse_imm(tail)
        if mode == "iJ":
            if sign == "-":
                raise DasmError("cannot invert label reference")
            return value
        return tail if sign == "+" else expr

    def lookup_reg(self, name: Optional[str]):
        """Returns (Reg, CType) if name is a register or a .type name."""
        if name is None:
            return None, None
        tp = self.types.get(name)
        if tp:
            if tp.reg is None:
                raise DasmError(f"type `{name}' has no register")
            return REGS[tp.reg], tp
        return REGS.get(name), None

    def parse_operand(self, param: str, isqword: bool = False) -> Operand:
        t = Operand()
        expr = param
        m = _RE_OPSIZE.fullmatch(param)
        if m:
            t.opsize, expr = OPSIZE_NAMES[m[1]], m[2]

        if expr.startswith("[") and expr.endswith("]"):
            self.parse_memory(t, expr[1:-1].strip())
            return t

        imm = _parse_imm32(expr, isqword)
        if imm is not None:
            if t.opsize:
                raise DasmError("bad operand size override")
            if 0xFFFFFF80 <= imm <= 0xFFFFFFFF:
                imm -= 1 << 32
            t.imm = imm
            t.mode = "i" + ("1" if imm == 1 else "") + ("S" if -128 <= imm <= 127 else "")
            return t

        m = _RE_WORD.fullmatch(expr)
        reg, tp = self.lookup_reg(m[1]) if m else (None, None)
        if reg is None:
            t.mode, t.imm = self.parse_imm(expr)
            if t.mode == "iJ":
                if t.opsize not in (None, "q"):
                    raise DasmError("bad operand size override")
                t.opsize = "q"
            return t

        tail = m[2]
        t.reg = reg.num
        if reg.num == -1:
            t.vreg, tail = _take_vreg(tail)
        if tail == "":
            # register
            if t.opsize:
                raise DasmError("bad operand size override")
            t.opsize = reg.size
            t.needrex = reg.needrex
            if reg.size == "f":
                t.mode = "fF" if reg.num == 0 else "f"
            elif reg.num == 0:
                t.mode = "rmR"
            elif reg.size == "b" and reg.num == 1 and reg.needrex is None:
                t.mode = "rmC"
            else:
                t.mode = "rm"
            return t

        # type->field, type[idx].field: memory at offsetof(field) from the type's register
        if tp is None:
            raise DasmError(f"bad operand `{param}'")
        t.mode = "xm"
        t.disp = tp.offset_expr(tail)
        return t

    def parse_memory(self, t: Operand, br: str) -> None:
        """Parses the inside of [base+index*scale+disp]."""
        t.mode = "xm"

        n = _parse_imm32(br)
        if n is not None:
            t.disp = n
            return

        m = _RE_WORD.fullmatch(br)
        reg, _ = self.lookup_reg(m[1]) if m else (None, None)
        if reg is None:
            t.disp = self.parse_disp("+" + br)
            return
        tail = m[2]
        t.reg = reg.num
        if reg.num == -1:
            t.vreg, tail = _take_vreg(tail)

        # [index*scale+disp]
        m = _RE_SCALE.fullmatch(tail)
        if m:
            if not _valid_index(reg):
                raise DasmError(f"bad index register in `[{br}]'")
            t.xsc = int(m[1]).bit_length() - 1
            t.xreg, t.vxreg = t.reg, t.vreg
            t.reg, t.vreg = None, None
            t.disp = self.parse_disp(m[2])
            return
        if not _addressable(reg):
            raise DasmError(f"bad base register in `[{br}]'")

        # [base+index*scale+disp]
        m = _RE_PLUS_WORD.fullmatch(tail)
        xreg, _ = self.lookup_reg(m[1]) if m else (None, None)
        if xreg is not None:
            if not _valid_index(xreg):
                raise DasmError(f"bad index register in `[{br}]'")
            tail = m[2]
            t.xreg = xreg.num
            if xreg.num == -1:
                t.vxreg, tail = _take_vreg(tail)
            m = _RE_SCALE.fullmatch(tail)
            if m:
                t.xsc = int(m[1]).bit_length() - 1
                tail = m[2]

        t.disp = self.parse_disp(tail)

    # -----------------------------------------------------------------------
    # Instruction encoder

    def has_instruction(self, op: str, nparams: int) -> bool:
        return f"{op}_{nparams}" in OPS or (op == "mov64" and nparams == 2)

    def instruction(self, op: str, params: List[str]) -> None:
        if op == "mov64":
            return self.mov64(params)
        template = OPS[f"{op}_{len(params)}"]
        if not params:
            return self.encode(template, [], "d", op, None)

        # Common operand size, and whether operand sizes differ
        args = [self.parse_operand(p) for p in params]
        sz, szmix, needrex = None, False, None
        for a in args:
            if a.opsize:
                if sz and sz != a.opsize:
                    szmix = True
                else:
                    sz = a.opsize
            if a.needrex is not None:
                if needrex is None:
                    needrex = a.needrex
                elif needrex != a.needrex:
                    raise DasmError("bad mix of byte-addressable registers")

        gotmatch = False
        pat = ""
        for alt in template.split("|"):
            szm, _, altpat = alt[len(args) :].partition(":")
            pat = altpat or pat
            if not all(c in a.mode for c, a in zip(alt, args)):
                continue
            gotmatch = True
            if szm.startswith("/"):
                if all(a.opsize == c for a, c in zip(args, szm[1:])):
                    return self.encode(pat, args, sz, op, needrex)
                continue
            szp = sz
            if szm.startswith("1"):
                szp, szmix = args[0].opsize, False
            elif szm.startswith("2"):
                szp, szmix = args[1].opsize, False
            if not szmix and (szm == "." or (szp is not None and szp in (szm or "qdwb"))):
                return self.encode(pat, args, szp, op, needrex)

        if not gotmatch:
            msg = "bad operand mode"
        elif szmix:
            msg = "mixed operand size"
        else:
            msg = "bad operand size" if sz else "missing operand size"
        modes = ",".join(a.mode[0] + (a.opsize or "?") for a in args)
        raise DasmError(f"{msg} in `{op} {modes}'")

    def encode(self, pat: str, args: List[Operand], sz: Optional[str], op: str, needrex: Optional[bool]) -> None:
        """Encodes one instruction following a template pattern (see
        fd_dasm_x86_ops.py for the pattern characters)."""
        self.reserve(6)

        opcode: Optional[int] = 0
        addin: Optional[Operand] = None  # register operand merged into the opcode
        vex: Optional[Vex] = None
        szov = sz
        narg = 0  # index of the next immediate operand
        rex = 0

        for c in pat + "|":
            if c in "0123456789ABCDEF":
                opcode = opcode * 16 + int(c, 16)
                addin = None
            elif c == "n":
                szov = None
            elif c == "X":
                rex = 8
            elif c == "L":
                vex.l = True
            elif c in "rR":
                i = "rR".index(c)
                addin = args[i]
                opcode += addin.reg % 8
                narg = max(narg, i + 1)
            elif c in "mM":
                if addin:
                    s = addin.reg
                    opcode -= s & 7
                else:
                    s = opcode & 15
                    opcode >>= 4
                i = "mM".index(c)
                t = args[i]
                narg = max(narg, i + 1)
                if szov == "q" and rex == 0:
                    rex = 8
                if t.reg is not None and t.reg > 7:
                    rex += 1
                if t.xreg is not None and t.xreg > 7:
                    rex += 2
                if s > 7:
                    rex += 4
                if needrex:
                    rex += 16
                vregxb = t.vreg is not None or t.vxreg is not None
                psz, sk = self.put_opcode(szov, opcode, rex, vex, s < 0, vregxb)
                opcode = None
                self.put_modrm_sib(t, pat[-1], s, addin.vreg if addin else None, psz, sk)
                addin = None
            elif c in "uvVw":
                # opcode so far is [prefix] 0F [38|3A]
                b = opcode & 255
                opcode >>= 8
                m = {0x38: 2, 0x3A: 3}.get(b, 1)
                if m != 1:
                    b = opcode & 255
                    opcode >>= 8
                if b != 0x0F:
                    raise DasmError(f"expected `0F', `0F38', or `0F3A' to precede `{c}' in pattern `{pat}' for `{op}'")
                v = args.pop("vVw".index(c)) if c != "u" else None
                p = {0x66: 1, 0xF3: 2, 0xF2: 3}.get(opcode & 255, 0)
                if p:
                    opcode >>= 8
                if opcode:
                    self.put_opcode(None, opcode, 0)
                    opcode = 0
                vex = Vex(m, p, v)
            else:
                if opcode is not None:
                    if szov == "q" and rex == 0:
                        rex = 8
                    if needrex:
                        rex += 16
                    if addin and addin.reg == -1:
                        psz, sk = self.put_opcode(szov, opcode - 7, rex, vex, True)
                        self.put_vreg("opcode", addin.vreg, psz, sk)
                    else:
                        if addin and addin.reg > 7:
                            rex += 1
                        self.put_opcode(szov, opcode, rex, vex)
                    opcode = None
                if c == "|":
                    break
                if c in "oO":
                    i = "oO".index(c)
                    self.put_imm32(args[i].disp)
                    narg = max(narg, i + 1)
                    continue

                # Everything else consumes the next operand as an immediate
                a = args[narg]
                narg += 1
                if a.mode == "iJ" and c != "J":
                    raise DasmError("bad operand size for label")
                if c == "S":
                    self.put_imm8s(a.imm)
                elif c == "U":
                    self.put_imm8(a.imm)
                elif c == "W":
                    self.put_imm16(a.imm)
                elif c == "i":
                    self.put_imm_sized(sz, a.imm)
                elif c == "I":
                    if a.mode == "iI":
                        self.put_action("IMM_WB" if sz == "w" else "IMM_DB", a.imm)
                    else:
                        self.put_imm_sized(sz, a.imm)
                elif c == "J":
                    if not isinstance(a.imm, Label):
                        raise DasmError("expected a label")
                    self.put_rel(a.imm)
                elif c == "s":
                    if a.reg < 0:
                        self.put_byte(0)
                        self.put_vreg("imm.hi", a.vreg)
                    else:
                        self.put_byte(a.reg << 4)
                else:
                    raise DasmError(f"bad char `{c}' in pattern `{pat}' for `{op}'")

    def mov64(self, params: List[str]) -> None:
        """mov64 reg, imm64"""
        self.reserve(2)
        a = self.parse_operand(params[0])
        if not a.mode.startswith("r") or a.opsize != "q":
            raise DasmError("bad operand mode")
        vreg = a.vreg if a.reg == -1 else None
        opcode = 0xB8 if a.reg == -1 else 0xB8 + (a.reg & 7)
        psz, sk = self.put_opcode(None, opcode, 9 if a.reg > 7 else 8, None, vreg is not None)
        self.put_vreg("opcode", vreg, psz, sk)
        self.put_action("IMM_D", f"(unsigned int)({params[1]})")
        self.put_action("IMM_D", f"(unsigned int)(({params[1]})>>32)")

    # -----------------------------------------------------------------------
    # Directives

    def label(self, text: str) -> None:
        self.reserve(2)
        if re.fullmatch(r"[1-9]", text):
            self.put_action("LABEL_LG", npos=1)
            self.put_raw(int(text))
        elif text.startswith("->"):
            self.put_action("LABEL_LG", npos=1)
            self.put_raw(self.global_label(text[2:]))
        elif text.startswith("=>"):
            self.put_action("LABEL_PC", text[2:])
        else:
            raise DasmError("bad label definition")

    def data(self, op: str, params: List[str]) -> None:
        sz = DATA_SIZES[op]
        for p in params:
            a = self.parse_operand(p, sz == "q")
            if a.mode not in ("i", "i1", "iS", "i1S", "iI") or a.opsize:
                raise DasmError(f"bad mode or size in `{p}'")
            if sz == "q":
                self.put_imm64(a.imm)
            else:
                self.put_imm_sized(sz, a.imm)
            self.reserve(2)

    def align(self, text: str) -> None:
        self.reserve(1)
        n = parse_int(text)
        if n is None:
            n = OPSIZE_BYTES.get(OPSIZE_NAMES.get(text, ""))
        if n is None or n not in (2, 4, 8, 16, 32, 64, 128, 256):
            raise DasmError("bad alignment")
        self.put_action("ALIGN", npos=1)
        self.put_raw(n - 1)

    def check_type_reg(self, reg: str) -> None:
        r = REGS.get(reg)
        if r is None or r.num < 0 or not _addressable(r):
            raise DasmError(f"bad base register `{reg}'")

    def terminate(self) -> None:
        self.put_raw(ACTION["STOP"])

    def dedupe(self) -> int:
        """Reuses an earlier identical chunk of the action list if any."""
        chunk = bytes(self.actions[self.put_ofs :])
        orig = bytes(self.actions[: self.put_ofs]).find(chunk)
        if orig < 0:
            return self.put_ofs
        del self.actions[self.put_ofs :]
        return orig

    def format_actions(self, name: str) -> str:
        actions = self.actions or [ACTION["STOP"]]
        lines = [f"static uchar const {name}[ {len(actions)} ] = {{"]
        for i in range(0, len(actions), 16):
            lines.append("  " + ",".join(f"{b:3d}" for b in actions[i : i + 16]) + ",")
        lines[-1] = lines[-1].rstrip(",")
        lines.append("};")
        return "\n".join(lines)


def _expr(n: Imm) -> str:
    """Returns n as a C expression."""
    if isinstance(n, Label):
        raise DasmError("label is not valid here")
    return str(n)


def _parse_imm32(expr: str, isqword: bool = False) -> Optional[int]:
    """Returns the value of an integer literal.  A literal that needs 64
    bits yields None for qword data (it is passed through as a C
    expression) and is an error elsewhere."""
    n = parse_int(expr)
    if n is None:
        return None
    if isqword:
        return n if -(1 << 31) <= n < (1 << 31) else None
    if not -(1 << 31) <= n < (1 << 32):
        raise DasmError(f"bad integer number `{expr}'")
    return n


def _take_vreg(tail: str) -> Tuple[str, str]:
    """Splits "(expr)rest" following an Rq/Rd/... register name."""
    split = take_parens(tail)
    if split is None:
        raise DasmError("bad variable register expression")
    return split[0], split[1].lstrip()
