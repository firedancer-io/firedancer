This directory contains a subset of DynASM from the LuaJIT project at
https://github.com/LuaJIT/LuaJIT

Files are copied exactly from commit
24c20c94e7db195b640854619577441f9b4bc6be, with no Firedancer specific
modifications.  Do not edit vendored files locally; update by
re-running `vendor.sh` against a new pinned commit.

Only the DynASM x86/x64 preprocessor and C header subset used for
dynamic machine code generation is vendored:
- dasm_proto.h: Core DynASM C interface
- dasm_x86.h: x86/x64 encoding engine
- dynasm/dynasm.lua: DynASM preprocessor
- dynasm/dasm_x86.lua: x86 architecture description module
- dynasm/dasm_x64.lua: x64 architecture description wrapper
- dynasm/dynasm_x86.lua: alias of dasm_x86.lua

For licensing information (MIT license), see LICENSE in this
directory and NOTICE in the root of this repo.
