#!/usr/bin/env python3
"""Tests for fd_dasm.py.  Run with: python3 test_fd_dasm.py

fixtures/<arch>.dasc exercise every operand form.  Their expected
output fixtures/<arch>.c was validated by assembling it and comparing
the machine code against DynASM.  Regenerate after an intended change:

    python3 fd_dasm.py -o fixtures/x86.c fixtures/x86.dasc"""

import os
import unittest

from fd_dasm import Translator
from fd_dasm_arm64 import logical_imm
from fd_dasm_common import DasmError, eval_const, parse_int, split_statement

HERE = os.path.dirname(os.path.abspath(__file__))


def translate(text: str, name: str = "t.dasc") -> str:
    return Translator(name).translate(text.split("\n"))


def puts(arch: str, *asm: str) -> list:
    """Assembles statements, returns the generated fd_dasm_put lines."""
    text = "\n".join([f"|.arch {arch}", "|.type ctx, ctx_t, " + ("rbx" if arch == "x64" else "x19")] + ["| " + a for a in asm])
    return [l.strip() for l in translate(text).split("\n") if "fd_dasm_put" in l]


class GoldenTest(unittest.TestCase):
    def check(self, arch: str) -> None:
        path = os.path.join(HERE, "fixtures", f"{arch}.dasc")
        with open(path) as f:
            got = Translator(path).translate(f.read().rstrip("\n").split("\n"))
        with open(os.path.join(HERE, "fixtures", f"{arch}.c")) as f:
            self.assertEqual(got, f.read())

    def test_x86(self):
        self.check("x86")

    def test_arm64(self):
        self.check("arm64")


class FrontEndTest(unittest.TestCase):
    def test_split_statement(self):
        self.assertEqual(split_statement("ret"), ("ret", []))
        self.assertEqual(split_statement("mov rax, [rcx+f(a, b)]"), ("mov", ["rax", "[rcx+f(a, b)]"]))
        self.assertEqual(split_statement("m, 1"), ("m", ["1"]))
        self.assertEqual(split_statement("stp x0, x1, [sp, #-16]!"), ("stp", ["x0", "x1", "[sp, #-16]!"]))
        with self.assertRaises(DasmError):
            split_statement("mov rax, (1")

    def test_consts(self):
        self.assertEqual(parse_int(" -0x10 "), -16)
        self.assertIsNone(parse_int("n"))
        with self.assertRaises(DasmError):
            parse_int("010")
        self.assertEqual(eval_const("(64-(3))%64"), 61)
        self.assertEqual(eval_const("31-(3)"), 28)
        self.assertIsNone(eval_const("sizeof(x)"))
        self.assertIsNone(eval_const("(0-1)%8"))  # C and Python disagree

    def test_passthrough_and_line_sync(self):
        out = translate("int a;\n|.arch x64\n| ret\nint b;").split("\n")
        self.assertIn("int a;", out)
        self.assertIn("//| ret", out)
        self.assertIn("fd_dasm_put( DASM, 0, NULL );", out)
        self.assertEqual(out[out.index("int b;") - 1], '#line 4 "t.dasc"')

    def test_put_arguments(self):
        (put,) = puts("x64", "mov Rq(r), [rcx+n]")
        self.assertTrue(put.endswith("(int const[]){ (int)((r)), (int)(n) } );"), put)

    def test_identical_chunks_share_actions(self):
        text = "|.arch x64\n| mov rax, rcx\nf();\n| mov rax, rcx\n"
        self.assertEqual(translate(text).count("fd_dasm_put( DASM, 0, NULL );"), 2)

    def test_macro(self):
        direct = puts("x64", "mov rax, ctx->cu", "sub rax, 5")
        macro = puts("x64", ".macro charge, reg, n", "mov reg, ctx->cu", "sub reg, n", ".endmacro", "charge rax, 5")
        self.assertEqual(direct, macro)

    def test_macro_param_inside_path(self):
        (put,) = puts("x64", ".macro ld, f", "mov rax, ctx->a.f", ".endmacro", "ld tlb_hi")
        self.assertIn("Dt1(->a.tlb_hi)", put)

    def test_globals(self):
        out = translate("|.arch x64\n|.globals g_\n|.globalnames names\n|->first:\n| jmp ->second\n|->second:")
        self.assertIn("enum {\n  g_first,\n  g_second,\n  g__MAX\n};", out)
        self.assertIn('  "first",\n  "second",\n  NULL\n};', out)


class ErrorTest(unittest.TestCase):
    def expect(self, text: str, *msgs: str) -> None:
        with self.assertRaises(DasmError) as cm:
            translate(text, "in.dasc")
        for msg in msgs:
            self.assertIn(msg, str(cm.exception))

    def test_location(self):
        self.expect("|.arch x64\nint x;\n| bogus rax", "in.dasc:3: error: unknown instruction `bogus'")

    def test_all_errors_reported(self):
        self.expect("|.arch x64\n| bogus\n| mov rax\n", "in.dasc:2:", "in.dasc:3: error: wrong number of operands for `mov'")

    def test_missing_arch(self):
        self.expect("| ret", "first statement must be .arch")
        self.expect("int x;", "missing .arch directive")
        self.expect("|.arch mips", "unknown arch `mips'")

    def test_macros(self):
        self.expect("|.arch x64\n|.macro m\n| ret", "in.dasc:2: error: unfinished .macro `m'")
        self.expect("|.arch x64\n|.endmacro", ".endmacro without .macro")
        self.expect("|.arch x64\n|.macro mov, a, b\n|.endmacro", "shadows an instruction")
        self.expect("|.arch x64\n|.macro m\n| m\n|.endmacro\n| m", "recursive invocation of macro `m'")
        self.expect("|.arch x64\n|.macro m\n| bogus\n|.endmacro\n| m", "in.dasc:5:", "in macro m (line 2): bogus")

    def test_unsupported_directives(self):
        for d in (".if 1", ".define a, b", ".include x", ".section code", ".space 4"):
            self.expect(f"|.arch x64\n|{d}", "unknown directive")

    def test_x86_operands(self):
        self.expect("|.arch x64\n| mov rax, ecx", "mixed operand size")
        self.expect("|.arch x64\n| mov [rax], 1", "missing operand size")
        self.expect("|.arch x64\n| mov ah, r8b", "bad mix of byte-addressable registers")
        self.expect("|.arch x64\n| mov rax, [rcx+rsp*2]", "bad index register")
        self.expect("|.arch x64\n| mov rax, [cx]", "bad base register")
        self.expect("|.arch x64\n| shl rax, 300", "unsigned immediate byte out of range")
        self.expect("|.arch x64\n| add rax, 0x1ffffffff", "bad integer number")
        self.expect("|.arch x64\n| mov Rq r, rax", "bad variable register expression")
        self.expect("|.arch x64\n| jmp &fn", "unsupported operand")
        self.expect("|.arch x64\n| .align 3", "bad alignment")
        self.expect("|.arch x64\n|.type t, t_t, cx", "bad base register `cx'")

    def test_arm64_operands(self):
        self.expect("|.arch arm64\n| add x0, w1, x2", "register size mismatch")
        self.expect("|.arch arm64\n| add x0, x1, #0x1001", "out of range immediate")
        self.expect("|.arch arm64\n| and x0, x1, #0", "out of range immediate")
        self.expect("|.arch arm64\n| ldr x0, [x1, #4096000]", "out of range immediate")
        self.expect("|.arch arm64\n| mov x0, x31", "bad register name")
        self.expect("|.arch arm64\n| b foo", "bad label `foo'")
        self.expect("|.arch arm64\n| csel x0, x1, x2, zz", "expected condition operand")
        self.expect("|.arch arm64\n| .long 0x1ffffffff", "bad immediate")


class Arm64ImmTest(unittest.TestCase):
    def test_logical_imm(self):
        # (N:immr:imms) from the Arm ARM
        self.assertEqual(logical_imm(0xFF), 0x1007)
        self.assertEqual(logical_imm(0x5555555555555555), 0x03C)
        self.assertEqual(logical_imm(0xFFFF0000FFFF0000), 0x40F)
        self.assertEqual(logical_imm(0xFFFFFFFFFFFFFFFE), 0x1FFE)
        self.assertEqual(logical_imm(0x8000000000000000), 0x1040)
        self.assertIsNone(logical_imm(0))
        self.assertIsNone(logical_imm(0xFFFFFFFFFFFFFFFF))
        self.assertIsNone(logical_imm(0x5))

    def test_logical_imm_matches_definition(self):
        """Decodes every encoding the reference way and checks the encoder inverts it."""
        mask = (1 << 64) - 1
        seen = {}
        for n in (0, 1):
            for imms in range(64):
                for immr in range(64):
                    length = ((n << 6) | (~imms & 0x3F)).bit_length() - 1
                    if length < 1:
                        continue
                    size = 1 << length
                    s, r = imms & (size - 1), immr & (size - 1)
                    if s == size - 1:
                        continue
                    elem = (1 << (s + 1)) - 1
                    elem = ((elem >> r) | (elem << (size - r))) & ((1 << size) - 1)
                    value = sum(elem << i for i in range(0, 64, size)) & mask
                    seen.setdefault(value, (n << 12) | (immr << 6) | imms)
        self.assertEqual(len(seen), 5334)
        for value, enc in seen.items():
            got = logical_imm(value)
            self.assertIsNotNone(got, hex(value))
            # immr is only significant modulo the element size
            self.assertEqual(got & 0x103F, enc & 0x103F, hex(value))


if __name__ == "__main__":
    unittest.main()
