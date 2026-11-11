# Derived from DynASM (https://luajit.org/dynasm.html).
# Copyright (C) 2005-2026 Mike Pall. All rights reserved.
# Released under the MIT license, see NOTICE.

"""x86-64 instruction templates.

Keys are "<mnemonic>_<operand count>".  Each template is a list of
"match:pattern" alternatives separated by "|"; the first alternative
whose match part accepts the operands is encoded.  An empty pattern
reuses the previous alternative's pattern.  Instructions without
operands have a bare pattern.

Match part: one mode character per operand, then the operand sizes.

  Operand modes (an operand has several, see parse_operand):
    r  register            R  rax/eax/ax/al     C  cl
    m  register or memory  x  memory
    i  immediate           S  imm fits int8     1  the constant 1
    I  immediate known only at run time
    f  x87 register        F  st0
    J  label

  Operand sizes (b w d q, t=tword, o=xmm, y=ymm):
    ""     same as "qdwb"
    "qd"   all sized operands share one of the listed sizes
    "1qd"  size is taken from operand 1 only (likewise "2")
    "."    sizes are ignored
    "/qd"  operand sizes are exactly q, d, ... in operand order

Pattern: hex digits accumulate the opcode, other characters act on it.

    n      no size adjustment (default: opcode-1 for b, 66 prefix for
           w, REX.W for q)
    X      force REX.W
    r R    add register number of operand 1 / 2 to the opcode
    m M    ModRM/SIB for operand 1 / 2.  The reg field is the last hex
           digit, or the register from a preceding r/R
    u      VEX prefix, vvvv unused
    v V w  VEX prefix, vvvv is operand 1 / 2 / 3 (which is then removed
           from the operand list)
    L      force VEX.L
    o O    32 bit displacement of operand 1 / 2
    s      imm4 from a register operand
    S U W  int8 / uint8 / uint16 immediate
    i      immediate of the operand size
    I      same, shortened to int8 at run time if it fits (opcode+2)
    J      rel32 branch target
"""

from typing import Dict

OPS: Dict[str, str] = {
    # 00-05: add...
    # 06: *push es
    # 07: *pop es
    # 08-0D: or...
    # 0E: *push cs
    # 0F: two byte opcode prefix
    # 10-15: adc...
    # 16: *push ss
    # 17: *pop ss
    # 18-1D: sbb...
    # 1E: *push ds
    # 1F: *pop ds
    # 20-25: and...
    "es_0": "26",
    # 27: *daa
    # 28-2D: sub...
    "cs_0": "2E",
    # 2F: *das
    # 30-35: xor...
    "ss_0": "36",
    # 37: *aaa
    # 38-3D: cmp...
    "ds_0": "3E",
    # 3F: *aas
    "inc_1": "m:FF0m",
    "dec_1": "m:FF1m",
    "push_1": "rq:n50r|rw:50r|mq:nFF6m|mw:FF6m|S.:6AS|ib:n6Ai|i.:68i",
    "pop_1": "rq:n58r|rw:58r|mq:n8F0m|mw:8F0m",
    # 60: *pusha, *pushad, *pushaw
    # 61: *popa, *popad, *popaw
    # 62: *bound rdw,x
    # 63: x86: *arpl mw,rw
    "movsxd_2": "rm/qd:63rM",
    "fs_0": "64",
    "gs_0": "65",
    "o16_0": "66",
    "a32_0": "67",
    # 68: push idw
    # 69: imul rdw,mdw,idw
    # 6A: push ib
    # 6B: imul rdw,mdw,S
    # 6C: *insb
    # 6D: *insd, *insw
    # 6E: *outsb
    # 6F: *outsd, *outsw
    # 70-7F: jcc lb
    # 80: add... mb,i
    # 81: add... mdw,i
    # 82: *undefined
    # 83: add... mdw,S
    "test_2": "mr:85Rm|rm:85rM|Ri:A9ri|mi:F70mi",
    # 86: xchg rb,mb
    # 87: xchg rdw,mdw
    # 88: mov mb,r
    # 89: mov mdw,r
    # 8A: mov r,mb
    # 8B: mov r,mdw
    # 8C: *mov mdw,seg
    "lea_2": "rx1dq:8DrM",
    # 8E: *mov seg,mdw
    # 8F: pop mdw
    "nop_0": "90",
    "xchg_2": "Rrqdw:90R|rRqdw:90r|rm:87rM|mr:87Rm",
    "cbw_0": "6698",
    "cwde_0": "98",
    "cdqe_0": "4898",
    "cwd_0": "6699",
    "cdq_0": "99",
    "cqo_0": "4899",
    # 9A: *call iw:idw
    "wait_0": "9B",
    "fwait_0": "9B",
    "pushf_0": "9C",
    "pushfq_0": "9C",
    "popf_0": "9D",
    "popfq_0": "9D",
    "sahf_0": "9E",
    "lahf_0": "9F",
    "mov_2": "OR:A3o|RO:A1O|mr:89Rm|rm:8BrM|rib:nB0ri|ridw:B8ri|mi:C70mi",
    "movsb_0": "A4",
    "movsw_0": "66A5",
    "movsd_0": "A5",
    "cmpsb_0": "A6",
    "cmpsw_0": "66A7",
    "cmpsd_0": "A7",
    # A8: test Rb,i
    # A9: test Rdw,i
    "stosb_0": "AA",
    "stosw_0": "66AB",
    "stosd_0": "AB",
    "lodsb_0": "AC",
    "lodsw_0": "66AD",
    "lodsd_0": "AD",
    "scasb_0": "AE",
    "scasw_0": "66AF",
    "scasd_0": "AF",
    # B0-B7: mov rb,i
    # B8-BF: mov rdw,i
    # C0: rol... mb,i
    # C1: rol... mdw,i
    "ret_1": "i.:nC2W",
    "ret_0": "C3",
    # C4: *les rdw,mq
    # C5: *lds rdw,mq
    # C6: mov mb,i
    # C7: mov mdw,i
    # C8: *enter iw,ib
    "leave_0": "C9",
    # CA: *retf iw
    # CB: *retf
    "int3_0": "CC",
    "int_1": "i.:nCDU",
    "into_0": "CE",
    # CF: *iret
    # D0: rol... mb,1
    # D1: rol... mdw,1
    # D2: rol... mb,cl
    # D3: rol... mb,cl
    # D4: *aam ib
    # D5: *aad ib
    # D6: *salc
    # D7: *xlat
    # D8-DF: floating point ops
    # E0: *loopne
    # E1: *loope
    # E2: *loop
    # E3: *jcxz, *jecxz
    # E4: *in Rb,ib
    # E5: *in Rdw,ib
    # E6: *out ib,Rb
    # E7: *out ib,Rdw
    "call_1": "mq:nFF2m|J.:E8nJ",
    "jmp_1": "mq:nFF4m|J.:E9nJ",
    # EA: *jmp iw:idw
    # EB: jmp ib
    # EC: *in Rb,dx
    # ED: *in Rdw,dx
    # EE: *out dx,Rb
    # EF: *out dx,Rdw
    "lock_0": "F0",
    "int1_0": "F1",
    "repne_0": "F2",
    "repnz_0": "F2",
    "rep_0": "F3",
    "repe_0": "F3",
    "repz_0": "F3",
    "endbr32_0": "F30F1EFB",
    "endbr64_0": "F30F1EFA",
    # F4: *hlt
    "cmc_0": "F5",
    # F6: test... mb,i; div... mb
    # F7: test... mdw,i; div... mdw
    "clc_0": "F8",
    "stc_0": "F9",
    # FA: *cli
    "cld_0": "FC",
    "std_0": "FD",
    # FE: inc... mb
    # FF: inc... mdw

    # misc ops
    "not_1": "m:F72m",
    "neg_1": "m:F73m",
    "mul_1": "m:F74m",
    "imul_1": "m:F75m",
    "div_1": "m:F76m",
    "idiv_1": "m:F77m",

    "imul_2": "rmqdw:0FAFrM|rIqdw:69rmI|rSqdw:6BrmS|riqdw:69rmi",
    "imul_3": "rmIqdw:69rMI|rmSqdw:6BrMS|rmiqdw:69rMi",

    "movzx_2": "rm/db:0FB6rM|rm/qb:|rm/wb:0FB6rM|rm/dw:0FB7rM|rm/qw:",
    "movsx_2": "rm/db:0FBErM|rm/qb:|rm/wb:0FBErM|rm/dw:0FBFrM|rm/qw:",

    "bswap_1": "rqd:0FC8r",
    "bsf_2": "rmqdw:0FBCrM",
    "bsr_2": "rmqdw:0FBDrM",
    "bt_2": "mrqdw:0FA3Rm|miqdw:0FBA4mU",
    "btc_2": "mrqdw:0FBBRm|miqdw:0FBA7mU",
    "btr_2": "mrqdw:0FB3Rm|miqdw:0FBA6mU",
    "bts_2": "mrqdw:0FABRm|miqdw:0FBA5mU",

    "shld_3": "mriqdw:0FA4RmU|mrC/qq:0FA5Rm|mrC/dd:|mrC/ww:",
    "shrd_3": "mriqdw:0FACRmU|mrC/qq:0FADRm|mrC/dd:|mrC/ww:",

    "rdtsc_0": "0F31",  # P1+
    "rdpmc_0": "0F33",  # P6+
    "cpuid_0": "0FA2",  # P1+

    # floating point ops
    "fst_1": "ff:DDD0r|xd:D92m|xq:nDD2m",
    "fstp_1": "ff:DDD8r|xd:D93m|xq:nDD3m|xt:DB7m",
    "fld_1": "ff:D9C0r|xd:D90m|xq:nDD0m|xt:DB5m",

    "fpop_0": "DDD8",  # Alias for fstp st0.

    "fist_1": "xw:nDF2m|xd:DB2m",
    "fistp_1": "xw:nDF3m|xd:DB3m|xq:nDF7m",
    "fild_1": "xw:nDF0m|xd:DB0m|xq:nDF5m",

    "fxch_0": "D9C9",
    "fxch_1": "ff:D9C8r",
    "fxch_2": "fFf:D9C8r|Fff:D9C8R",

    "fucom_1": "ff:DDE0r",
    "fucom_2": "Fff:DDE0R",
    "fucomp_1": "ff:DDE8r",
    "fucomp_2": "Fff:DDE8R",
    "fucomi_1": "ff:DBE8r",  # P6+
    "fucomi_2": "Fff:DBE8R",  # P6+
    "fucomip_1": "ff:DFE8r",  # P6+
    "fucomip_2": "Fff:DFE8R",  # P6+
    "fcomi_1": "ff:DBF0r",  # P6+
    "fcomi_2": "Fff:DBF0R",  # P6+
    "fcomip_1": "ff:DFF0r",  # P6+
    "fcomip_2": "Fff:DFF0R",  # P6+
    "fucompp_0": "DAE9",
    "fcompp_0": "DED9",

    "fldenv_1": "x.:D94m",
    "fnstenv_1": "x.:D96m",
    "fstenv_1": "x.:9BD96m",
    "fldcw_1": "xw:nD95m",
    "fstcw_1": "xw:n9BD97m",
    "fnstcw_1": "xw:nD97m",
    "fstsw_1": "Rw:n9BDFE0|xw:n9BDD7m",
    "fnstsw_1": "Rw:nDFE0|xw:nDD7m",
    "fclex_0": "9BDBE2",
    "fnclex_0": "DBE2",

    "fnop_0": "D9D0",
    # D9D1-D9DF: unassigned

    "fchs_0": "D9E0",
    "fabs_0": "D9E1",
    # D9E2: unassigned
    # D9E3: unassigned
    "ftst_0": "D9E4",
    "fxam_0": "D9E5",
    # D9E6: unassigned
    # D9E7: unassigned
    "fld1_0": "D9E8",
    "fldl2t_0": "D9E9",
    "fldl2e_0": "D9EA",
    "fldpi_0": "D9EB",
    "fldlg2_0": "D9EC",
    "fldln2_0": "D9ED",
    "fldz_0": "D9EE",
    # D9EF: unassigned

    "f2xm1_0": "D9F0",
    "fyl2x_0": "D9F1",
    "fptan_0": "D9F2",
    "fpatan_0": "D9F3",
    "fxtract_0": "D9F4",
    "fprem1_0": "D9F5",
    "fdecstp_0": "D9F6",
    "fincstp_0": "D9F7",
    "fprem_0": "D9F8",
    "fyl2xp1_0": "D9F9",
    "fsqrt_0": "D9FA",
    "fsincos_0": "D9FB",
    "frndint_0": "D9FC",
    "fscale_0": "D9FD",
    "fsin_0": "D9FE",
    "fcos_0": "D9FF",

    # SSE, SSE2
    "andnpd_2": "rmo:660F55rM",
    "andnps_2": "rmo:0F55rM",
    "andpd_2": "rmo:660F54rM",
    "andps_2": "rmo:0F54rM",
    "clflush_1": "x.:0FAE7m",
    "cmppd_3": "rmio:660FC2rMU",
    "cmpps_3": "rmio:0FC2rMU",
    "cmpsd_3": "rrio:F20FC2rMU|rxi/oq:",
    "cmpss_3": "rrio:F30FC2rMU|rxi/od:",
    "comisd_2": "rro:660F2FrM|rx/oq:",
    "comiss_2": "rro:0F2FrM|rx/od:",
    "cvtdq2pd_2": "rro:F30FE6rM|rx/oq:",
    "cvtdq2ps_2": "rmo:0F5BrM",
    "cvtpd2dq_2": "rmo:F20FE6rM",
    "cvtpd2ps_2": "rmo:660F5ArM",
    "cvtpi2pd_2": "rx/oq:660F2ArM",
    "cvtpi2ps_2": "rx/oq:0F2ArM",
    "cvtps2dq_2": "rmo:660F5BrM",
    "cvtps2pd_2": "rro:0F5ArM|rx/oq:",
    "cvtsd2si_2": "rr/do:F20F2DrM|rr/qo:|rx/dq:|rxq:",
    "cvtsd2ss_2": "rro:F20F5ArM|rx/oq:",
    "cvtsi2sd_2": "rm/od:F20F2ArM|rm/oq:F20F2ArXM",
    "cvtsi2ss_2": "rm/od:F30F2ArM|rm/oq:F30F2ArXM",
    "cvtss2sd_2": "rro:F30F5ArM|rx/od:",
    "cvtss2si_2": "rr/do:F30F2DrM|rr/qo:|rxd:|rx/qd:",
    "cvttpd2dq_2": "rmo:660FE6rM",
    "cvttps2dq_2": "rmo:F30F5BrM",
    "cvttsd2si_2": "rr/do:F20F2CrM|rr/qo:|rx/dq:|rxq:",
    "cvttss2si_2": "rr/do:F30F2CrM|rr/qo:|rxd:|rx/qd:",
    "fxsave_1": "x.:0FAE0m",
    "fxrstor_1": "x.:0FAE1m",
    "ldmxcsr_1": "xd:0FAE2m",
    "lfence_0": "0FAEE8",
    "maskmovdqu_2": "rro:660FF7rM",
    "mfence_0": "0FAEF0",
    "movapd_2": "rmo:660F28rM|mro:660F29Rm",
    "movaps_2": "rmo:0F28rM|mro:0F29Rm",
    "movd_2": "rm/od:660F6ErM|mr/do:660F7ERm",
    "movdqa_2": "rmo:660F6FrM|mro:660F7FRm",
    "movdqu_2": "rmo:F30F6FrM|mro:F30F7FRm",
    "movhlps_2": "rro:0F12rM",
    "movhpd_2": "rx/oq:660F16rM|xr/qo:n660F17Rm",
    "movhps_2": "rx/oq:0F16rM|xr/qo:n0F17Rm",
    "movlhps_2": "rro:0F16rM",
    "movlpd_2": "rx/oq:660F12rM|xr/qo:n660F13Rm",
    "movlps_2": "rx/oq:0F12rM|xr/qo:n0F13Rm",
    "movmskpd_2": "rr/do:660F50rM",
    "movmskps_2": "rr/do:0F50rM",
    "movntdq_2": "xro:660FE7Rm",
    "movnti_2": "xrqd:0FC3Rm",
    "movntpd_2": "xro:660F2BRm",
    "movntps_2": "xro:0F2BRm",
    "movq_2": "rro:F30F7ErM|rx/oq:|xr/qo:n660FD6Rm|rm/oq:660F6ErXM|mr/qo:660F7ERm",
    "movsd_2": "rro:F20F10rM|rx/oq:|xr/qo:nF20F11Rm",
    "movss_2": "rro:F30F10rM|rx/od:|xr/do:F30F11Rm",
    "movupd_2": "rmo:660F10rM|mro:660F11Rm",
    "movups_2": "rmo:0F10rM|mro:0F11Rm",
    "orpd_2": "rmo:660F56rM",
    "orps_2": "rmo:0F56rM",
    "pause_0": "F390",
    "pextrw_3": "rri/do:660FC5rMU|xri/wo:660F3A15nRmU",  # Mem op: SSE4.1 only.
    "pinsrw_3": "rri/od:660FC4rMU|rxi/ow:",
    "pmovmskb_2": "rr/do:660FD7rM",
    "prefetchnta_1": "xb:n0F180m",
    "prefetcht0_1": "xb:n0F181m",
    "prefetcht1_1": "xb:n0F182m",
    "prefetcht2_1": "xb:n0F183m",
    "pshufd_3": "rmio:660F70rMU",
    "pshufhw_3": "rmio:F30F70rMU",
    "pshuflw_3": "rmio:F20F70rMU",
    "pslld_2": "rmo:660FF2rM|rio:660F726mU",
    "pslldq_2": "rio:660F737mU",
    "psllq_2": "rmo:660FF3rM|rio:660F736mU",
    "psllw_2": "rmo:660FF1rM|rio:660F716mU",
    "psrad_2": "rmo:660FE2rM|rio:660F724mU",
    "psraw_2": "rmo:660FE1rM|rio:660F714mU",
    "psrld_2": "rmo:660FD2rM|rio:660F722mU",
    "psrldq_2": "rio:660F733mU",
    "psrlq_2": "rmo:660FD3rM|rio:660F732mU",
    "psrlw_2": "rmo:660FD1rM|rio:660F712mU",
    "rcpps_2": "rmo:0F53rM",
    "rcpss_2": "rro:F30F53rM|rx/od:",
    "rsqrtps_2": "rmo:0F52rM",
    "rsqrtss_2": "rmo:F30F52rM",
    "sfence_0": "0FAEF8",
    "shufpd_3": "rmio:660FC6rMU",
    "shufps_3": "rmio:0FC6rMU",
    "stmxcsr_1": "xd:0FAE3m",
    "ucomisd_2": "rro:660F2ErM|rx/oq:",
    "ucomiss_2": "rro:0F2ErM|rx/od:",
    "unpckhpd_2": "rmo:660F15rM",
    "unpckhps_2": "rmo:0F15rM",
    "unpcklpd_2": "rmo:660F14rM",
    "unpcklps_2": "rmo:0F14rM",
    "xorpd_2": "rmo:660F57rM",
    "xorps_2": "rmo:0F57rM",

    # SSE3 ops
    "fisttp_1": "xw:nDF1m|xd:DB1m|xq:nDD1m",
    "addsubpd_2": "rmo:660FD0rM",
    "addsubps_2": "rmo:F20FD0rM",
    "haddpd_2": "rmo:660F7CrM",
    "haddps_2": "rmo:F20F7CrM",
    "hsubpd_2": "rmo:660F7DrM",
    "hsubps_2": "rmo:F20F7DrM",
    "lddqu_2": "rxo:F20FF0rM",
    "movddup_2": "rmo:F20F12rM",
    "movshdup_2": "rmo:F30F16rM",
    "movsldup_2": "rmo:F30F12rM",

    # SSSE3 ops
    "pabsb_2": "rmo:660F381CrM",
    "pabsd_2": "rmo:660F381ErM",
    "pabsw_2": "rmo:660F381DrM",
    "palignr_3": "rmio:660F3A0FrMU",
    "phaddd_2": "rmo:660F3802rM",
    "phaddsw_2": "rmo:660F3803rM",
    "phaddw_2": "rmo:660F3801rM",
    "phsubd_2": "rmo:660F3806rM",
    "phsubsw_2": "rmo:660F3807rM",
    "phsubw_2": "rmo:660F3805rM",
    "pmaddubsw_2": "rmo:660F3804rM",
    "pmulhrsw_2": "rmo:660F380BrM",
    "pshufb_2": "rmo:660F3800rM",
    "psignb_2": "rmo:660F3808rM",
    "psignd_2": "rmo:660F380ArM",
    "psignw_2": "rmo:660F3809rM",

    # SSE4.1 ops
    "blendpd_3": "rmio:660F3A0DrMU",
    "blendps_3": "rmio:660F3A0CrMU",
    "blendvpd_3": "rmRo:660F3815rM",
    "blendvps_3": "rmRo:660F3814rM",
    "dppd_3": "rmio:660F3A41rMU",
    "dpps_3": "rmio:660F3A40rMU",
    "extractps_3": "mri/do:660F3A17RmU|rri/qo:660F3A17RXmU",
    "insertps_3": "rrio:660F3A21rMU|rxi/od:",
    "movntdqa_2": "rxo:660F382ArM",
    "mpsadbw_3": "rmio:660F3A42rMU",
    "packusdw_2": "rmo:660F382BrM",
    "pblendvb_3": "rmRo:660F3810rM",
    "pblendw_3": "rmio:660F3A0ErMU",
    "pcmpeqq_2": "rmo:660F3829rM",
    "pextrb_3": "rri/do:660F3A14nRmU|rri/qo:|xri/bo:",
    "pextrd_3": "mri/do:660F3A16RmU",
    "pextrq_3": "mri/qo:660F3A16RmU",
    # pextrw is SSE2, mem operand is SSE4.1 only
    "phminposuw_2": "rmo:660F3841rM",
    "pinsrb_3": "rri/od:660F3A20nrMU|rxi/ob:",
    "pinsrd_3": "rmi/od:660F3A22rMU",
    "pinsrq_3": "rmi/oq:660F3A22rXMU",
    "pmaxsb_2": "rmo:660F383CrM",
    "pmaxsd_2": "rmo:660F383DrM",
    "pmaxud_2": "rmo:660F383FrM",
    "pmaxuw_2": "rmo:660F383ErM",
    "pminsb_2": "rmo:660F3838rM",
    "pminsd_2": "rmo:660F3839rM",
    "pminud_2": "rmo:660F383BrM",
    "pminuw_2": "rmo:660F383ArM",
    "pmovsxbd_2": "rro:660F3821rM|rx/od:",
    "pmovsxbq_2": "rro:660F3822rM|rx/ow:",
    "pmovsxbw_2": "rro:660F3820rM|rx/oq:",
    "pmovsxdq_2": "rro:660F3825rM|rx/oq:",
    "pmovsxwd_2": "rro:660F3823rM|rx/oq:",
    "pmovsxwq_2": "rro:660F3824rM|rx/od:",
    "pmovzxbd_2": "rro:660F3831rM|rx/od:",
    "pmovzxbq_2": "rro:660F3832rM|rx/ow:",
    "pmovzxbw_2": "rro:660F3830rM|rx/oq:",
    "pmovzxdq_2": "rro:660F3835rM|rx/oq:",
    "pmovzxwd_2": "rro:660F3833rM|rx/oq:",
    "pmovzxwq_2": "rro:660F3834rM|rx/od:",
    "pmuldq_2": "rmo:660F3828rM",
    "pmulld_2": "rmo:660F3840rM",
    "ptest_2": "rmo:660F3817rM",
    "roundpd_3": "rmio:660F3A09rMU",
    "roundps_3": "rmio:660F3A08rMU",
    "roundsd_3": "rrio:660F3A0BrMU|rxi/oq:",
    "roundss_3": "rrio:660F3A0ArMU|rxi/od:",

    # SSE4.2 ops
    "crc32_2": "rmqd:F20F38F1rM|rm/dw:66F20F38F1rM|rm/db:F20F38F0rM|rm/qb:",
    "pcmpestri_3": "rmio:660F3A61rMU",
    "pcmpestrm_3": "rmio:660F3A60rMU",
    "pcmpgtq_2": "rmo:660F3837rM",
    "pcmpistri_3": "rmio:660F3A63rMU",
    "pcmpistrm_3": "rmio:660F3A62rMU",
    "popcnt_2": "rmqdw:F30FB8rM",

    # SSE4a
    "extrq_2": "rro:660F79rM",
    "extrq_3": "riio:660F780mUU",
    "insertq_2": "rro:F20F79rM",
    "insertq_4": "rriio:F20F78rMUU",
    "lzcnt_2": "rmqdw:F30FBDrM",
    "movntsd_2": "xr/qo:nF20F2BRm",
    "movntss_2": "xr/do:F30F2BRm",
    # popcnt is also in SSE4.2

    # AES-NI
    "aesdec_2": "rmo:660F38DErM",
    "aesdeclast_2": "rmo:660F38DFrM",
    "aesenc_2": "rmo:660F38DCrM",
    "aesenclast_2": "rmo:660F38DDrM",
    "aesimc_2": "rmo:660F38DBrM",
    "aeskeygenassist_3": "rmio:660F3ADFrMU",
    "pclmulqdq_3": "rmio:660F3A44rMU",

    # AVX FP ops
    "vaddsubpd_3": "rrmoy:660FVD0rM",
    "vaddsubps_3": "rrmoy:F20FVD0rM",
    "vandpd_3": "rrmoy:660FV54rM",
    "vandps_3": "rrmoy:0FV54rM",
    "vandnpd_3": "rrmoy:660FV55rM",
    "vandnps_3": "rrmoy:0FV55rM",
    "vblendpd_4": "rrmioy:660F3AV0DrMU",
    "vblendps_4": "rrmioy:660F3AV0CrMU",
    "vblendvpd_4": "rrmroy:660F3AV4BrMs",
    "vblendvps_4": "rrmroy:660F3AV4ArMs",
    "vbroadcastf128_2": "rx/yo:660F38u1ArM",
    "vcmppd_4": "rrmioy:660FVC2rMU",
    "vcmpps_4": "rrmioy:0FVC2rMU",
    "vcmpsd_4": "rrrio:F20FVC2rMU|rrxi/ooq:",
    "vcmpss_4": "rrrio:F30FVC2rMU|rrxi/ood:",
    "vcomisd_2": "rro:660Fu2FrM|rx/oq:",
    "vcomiss_2": "rro:0Fu2FrM|rx/od:",
    "vcvtdq2pd_2": "rro:F30FuE6rM|rx/oq:|rm/yo:",
    "vcvtdq2ps_2": "rmoy:0Fu5BrM",
    "vcvtpd2dq_2": "rmoy:F20FuE6rM",
    "vcvtpd2ps_2": "rmoy:660Fu5ArM",
    "vcvtps2dq_2": "rmoy:660Fu5BrM",
    "vcvtps2pd_2": "rro:0Fu5ArM|rx/oq:|rm/yo:",
    "vcvtsd2si_2": "rr/do:F20Fu2DrM|rx/dq:|rr/qo:|rxq:",
    "vcvtsd2ss_3": "rrro:F20FV5ArM|rrx/ooq:",
    "vcvtsi2sd_3": "rrm/ood:F20FV2ArM|rrm/ooq:F20FVX2ArM",
    "vcvtsi2ss_3": "rrm/ood:F30FV2ArM|rrm/ooq:F30FVX2ArM",
    "vcvtss2sd_3": "rrro:F30FV5ArM|rrx/ood:",
    "vcvtss2si_2": "rr/do:F30Fu2DrM|rxd:|rr/qo:|rx/qd:",
    "vcvttpd2dq_2": "rmo:660FuE6rM|rm/oy:660FuLE6rM",
    "vcvttps2dq_2": "rmoy:F30Fu5BrM",
    "vcvttsd2si_2": "rr/do:F20Fu2CrM|rx/dq:|rr/qo:|rxq:",
    "vcvttss2si_2": "rr/do:F30Fu2CrM|rxd:|rr/qo:|rx/qd:",
    "vdppd_4": "rrmio:660F3AV41rMU",
    "vdpps_4": "rrmioy:660F3AV40rMU",
    "vextractf128_3": "mri/oy:660F3AuL19RmU",
    "vextractps_3": "mri/do:660F3Au17RmU",
    "vhaddpd_3": "rrmoy:660FV7CrM",
    "vhaddps_3": "rrmoy:F20FV7CrM",
    "vhsubpd_3": "rrmoy:660FV7DrM",
    "vhsubps_3": "rrmoy:F20FV7DrM",
    "vinsertf128_4": "rrmi/yyo:660F3AV18rMU",
    "vinsertps_4": "rrrio:660F3AV21rMU|rrxi/ood:",
    "vldmxcsr_1": "xd:0FuAE2m",
    "vmaskmovps_3": "rrxoy:660F38V2CrM|xrroy:660F38V2ERm",
    "vmaskmovpd_3": "rrxoy:660F38V2DrM|xrroy:660F38V2FRm",
    "vmovapd_2": "rmoy:660Fu28rM|mroy:660Fu29Rm",
    "vmovaps_2": "rmoy:0Fu28rM|mroy:0Fu29Rm",
    "vmovd_2": "rm/od:660Fu6ErM|mr/do:660Fu7ERm",
    "vmovq_2": "rro:F30Fu7ErM|rx/oq:|xr/qo:660FuD6Rm|rm/oq:660FuX6ErM|mr/qo:660Fu7ERm",
    "vmovddup_2": "rmy:F20Fu12rM|rro:|rx/oq:",
    "vmovhlps_3": "rrro:0FV12rM",
    "vmovhpd_2": "xr/qo:660Fu17Rm",
    "vmovhpd_3": "rrx/ooq:660FV16rM",
    "vmovhps_2": "xr/qo:0Fu17Rm",
    "vmovhps_3": "rrx/ooq:0FV16rM",
    "vmovlhps_3": "rrro:0FV16rM",
    "vmovlpd_2": "xr/qo:660Fu13Rm",
    "vmovlpd_3": "rrx/ooq:660FV12rM",
    "vmovlps_2": "xr/qo:0Fu13Rm",
    "vmovlps_3": "rrx/ooq:0FV12rM",
    "vmovmskpd_2": "rr/do:660Fu50rM|rr/dy:660FuL50rM",
    "vmovmskps_2": "rr/do:0Fu50rM|rr/dy:0FuL50rM",
    "vmovntpd_2": "xroy:660Fu2BRm",
    "vmovntps_2": "xroy:0Fu2BRm",
    "vmovsd_2": "rx/oq:F20Fu10rM|xr/qo:F20Fu11Rm",
    "vmovsd_3": "rrro:F20FV10rM",
    "vmovshdup_2": "rmoy:F30Fu16rM",
    "vmovsldup_2": "rmoy:F30Fu12rM",
    "vmovss_2": "rx/od:F30Fu10rM|xr/do:F30Fu11Rm",
    "vmovss_3": "rrro:F30FV10rM",
    "vmovupd_2": "rmoy:660Fu10rM|mroy:660Fu11Rm",
    "vmovups_2": "rmoy:0Fu10rM|mroy:0Fu11Rm",
    "vorpd_3": "rrmoy:660FV56rM",
    "vorps_3": "rrmoy:0FV56rM",
    "vpermilpd_3": "rrmoy:660F38V0DrM|rmioy:660F3Au05rMU",
    "vpermilps_3": "rrmoy:660F38V0CrM|rmioy:660F3Au04rMU",
    "vperm2f128_4": "rrmiy:660F3AV06rMU",
    "vptestpd_2": "rmoy:660F38u0FrM",
    "vptestps_2": "rmoy:660F38u0ErM",
    "vrcpps_2": "rmoy:0Fu53rM",
    "vrcpss_3": "rrro:F30FV53rM|rrx/ood:",
    "vrsqrtps_2": "rmoy:0Fu52rM",
    "vrsqrtss_3": "rrro:F30FV52rM|rrx/ood:",
    "vroundpd_3": "rmioy:660F3Au09rMU",
    "vroundps_3": "rmioy:660F3Au08rMU",
    "vroundsd_4": "rrrio:660F3AV0BrMU|rrxi/ooq:",
    "vroundss_4": "rrrio:660F3AV0ArMU|rrxi/ood:",
    "vshufpd_4": "rrmioy:660FVC6rMU",
    "vshufps_4": "rrmioy:0FVC6rMU",
    "vsqrtps_2": "rmoy:0Fu51rM",
    "vsqrtss_2": "rro:F30Fu51rM|rx/od:",
    "vsqrtpd_2": "rmoy:660Fu51rM",
    "vsqrtsd_2": "rro:F20Fu51rM|rx/oq:",
    "vstmxcsr_1": "xd:0FuAE3m",
    "vucomisd_2": "rro:660Fu2ErM|rx/oq:",
    "vucomiss_2": "rro:0Fu2ErM|rx/od:",
    "vunpckhpd_3": "rrmoy:660FV15rM",
    "vunpckhps_3": "rrmoy:0FV15rM",
    "vunpcklpd_3": "rrmoy:660FV14rM",
    "vunpcklps_3": "rrmoy:0FV14rM",
    "vxorpd_3": "rrmoy:660FV57rM",
    "vxorps_3": "rrmoy:0FV57rM",
    "vzeroall_0": "0FuL77",
    "vzeroupper_0": "0Fu77",

    # AVX2 FP ops
    "vbroadcastss_2": "rx/od:660F38u18rM|rx/yd:|rro:|rr/yo:",
    "vbroadcastsd_2": "rx/yq:660F38u19rM|rr/yo:",
    # *vgather* (!vsib)
    "vpermpd_3": "rmiy:660F3AuX01rMU",
    "vpermps_3": "rrmy:660F38V16rM",

    # AVX, AVX2 integer ops
    # In general, xmm requires AVX, ymm requires AVX2.
    "vaesdec_3": "rrmo:660F38VDErM",
    "vaesdeclast_3": "rrmo:660F38VDFrM",
    "vaesenc_3": "rrmo:660F38VDCrM",
    "vaesenclast_3": "rrmo:660F38VDDrM",
    "vaesimc_2": "rmo:660F38uDBrM",
    "vaeskeygenassist_3": "rmio:660F3AuDFrMU",
    "vlddqu_2": "rxoy:F20FuF0rM",
    "vmaskmovdqu_2": "rro:660FuF7rM",
    "vmovdqa_2": "rmoy:660Fu6FrM|mroy:660Fu7FRm",
    "vmovdqu_2": "rmoy:F30Fu6FrM|mroy:F30Fu7FRm",
    "vmovntdq_2": "xroy:660FuE7Rm",
    "vmovntdqa_2": "rxoy:660F38u2ArM",
    "vmpsadbw_4": "rrmioy:660F3AV42rMU",
    "vpabsb_2": "rmoy:660F38u1CrM",
    "vpabsd_2": "rmoy:660F38u1ErM",
    "vpabsw_2": "rmoy:660F38u1DrM",
    "vpackusdw_3": "rrmoy:660F38V2BrM",
    "vpalignr_4": "rrmioy:660F3AV0FrMU",
    "vpblendvb_4": "rrmroy:660F3AV4CrMs",
    "vpblendw_4": "rrmioy:660F3AV0ErMU",
    "vpclmulqdq_4": "rrmio:660F3AV44rMU",
    "vpcmpeqq_3": "rrmoy:660F38V29rM",
    "vpcmpestri_3": "rmio:660F3Au61rMU",
    "vpcmpestrm_3": "rmio:660F3Au60rMU",
    "vpcmpgtq_3": "rrmoy:660F38V37rM",
    "vpcmpistri_3": "rmio:660F3Au63rMU",
    "vpcmpistrm_3": "rmio:660F3Au62rMU",
    "vpextrb_3": "rri/do:660F3Au14nRmU|rri/qo:|xri/bo:",
    "vpextrw_3": "rri/do:660FuC5rMU|xri/wo:660F3Au15nRmU",
    "vpextrd_3": "mri/do:660F3Au16RmU",
    "vpextrq_3": "mri/qo:660F3Au16RmU",
    "vphaddw_3": "rrmoy:660F38V01rM",
    "vphaddd_3": "rrmoy:660F38V02rM",
    "vphaddsw_3": "rrmoy:660F38V03rM",
    "vphminposuw_2": "rmo:660F38u41rM",
    "vphsubw_3": "rrmoy:660F38V05rM",
    "vphsubd_3": "rrmoy:660F38V06rM",
    "vphsubsw_3": "rrmoy:660F38V07rM",
    "vpinsrb_4": "rrri/ood:660F3AV20rMU|rrxi/oob:",
    "vpinsrw_4": "rrri/ood:660FVC4rMU|rrxi/oow:",
    "vpinsrd_4": "rrmi/ood:660F3AV22rMU",
    "vpinsrq_4": "rrmi/ooq:660F3AVX22rMU",
    "vpmaddubsw_3": "rrmoy:660F38V04rM",
    "vpmaxsb_3": "rrmoy:660F38V3CrM",
    "vpmaxsd_3": "rrmoy:660F38V3DrM",
    "vpmaxuw_3": "rrmoy:660F38V3ErM",
    "vpmaxud_3": "rrmoy:660F38V3FrM",
    "vpminsb_3": "rrmoy:660F38V38rM",
    "vpminsd_3": "rrmoy:660F38V39rM",
    "vpminuw_3": "rrmoy:660F38V3ArM",
    "vpminud_3": "rrmoy:660F38V3BrM",
    "vpmovmskb_2": "rr/do:660FuD7rM|rr/dy:660FuLD7rM",
    "vpmovsxbw_2": "rroy:660F38u20rM|rx/oq:|rx/yo:",
    "vpmovsxbd_2": "rroy:660F38u21rM|rx/od:|rx/yq:",
    "vpmovsxbq_2": "rroy:660F38u22rM|rx/ow:|rx/yd:",
    "vpmovsxwd_2": "rroy:660F38u23rM|rx/oq:|rx/yo:",
    "vpmovsxwq_2": "rroy:660F38u24rM|rx/od:|rx/yq:",
    "vpmovsxdq_2": "rroy:660F38u25rM|rx/oq:|rx/yo:",
    "vpmovzxbw_2": "rroy:660F38u30rM|rx/oq:|rx/yo:",
    "vpmovzxbd_2": "rroy:660F38u31rM|rx/od:|rx/yq:",
    "vpmovzxbq_2": "rroy:660F38u32rM|rx/ow:|rx/yd:",
    "vpmovzxwd_2": "rroy:660F38u33rM|rx/oq:|rx/yo:",
    "vpmovzxwq_2": "rroy:660F38u34rM|rx/od:|rx/yq:",
    "vpmovzxdq_2": "rroy:660F38u35rM|rx/oq:|rx/yo:",
    "vpmuldq_3": "rrmoy:660F38V28rM",
    "vpmulhrsw_3": "rrmoy:660F38V0BrM",
    "vpmulld_3": "rrmoy:660F38V40rM",
    "vpshufb_3": "rrmoy:660F38V00rM",
    "vpshufd_3": "rmioy:660Fu70rMU",
    "vpshufhw_3": "rmioy:F30Fu70rMU",
    "vpshuflw_3": "rmioy:F20Fu70rMU",
    "vpsignb_3": "rrmoy:660F38V08rM",
    "vpsignw_3": "rrmoy:660F38V09rM",
    "vpsignd_3": "rrmoy:660F38V0ArM",
    "vpslldq_3": "rrioy:660Fv737mU",
    "vpsllw_3": "rrmoy:660FVF1rM|rrioy:660Fv716mU",
    "vpslld_3": "rrmoy:660FVF2rM|rrioy:660Fv726mU",
    "vpsllq_3": "rrmoy:660FVF3rM|rrioy:660Fv736mU",
    "vpsraw_3": "rrmoy:660FVE1rM|rrioy:660Fv714mU",
    "vpsrad_3": "rrmoy:660FVE2rM|rrioy:660Fv724mU",
    "vpsrldq_3": "rrioy:660Fv733mU",
    "vpsrlw_3": "rrmoy:660FVD1rM|rrioy:660Fv712mU",
    "vpsrld_3": "rrmoy:660FVD2rM|rrioy:660Fv722mU",
    "vpsrlq_3": "rrmoy:660FVD3rM|rrioy:660Fv732mU",
    "vptest_2": "rmoy:660F38u17rM",

    # AVX2 integer ops
    "vbroadcasti128_2": "rx/yo:660F38u5ArM",
    "vinserti128_4": "rrmi/yyo:660F3AV38rMU",
    "vextracti128_3": "mri/oy:660F3AuL39RmU",
    "vpblendd_4": "rrmioy:660F3AV02rMU",
    "vpbroadcastb_2": "rro:660F38u78rM|rx/ob:|rr/yo:|rx/yb:",
    "vpbroadcastw_2": "rro:660F38u79rM|rx/ow:|rr/yo:|rx/yw:",
    "vpbroadcastd_2": "rro:660F38u58rM|rx/od:|rr/yo:|rx/yd:",
    "vpbroadcastq_2": "rro:660F38u59rM|rx/oq:|rr/yo:|rx/yq:",
    "vpermd_3": "rrmy:660F38V36rM",
    "vpermq_3": "rmiy:660F3AuX00rMU",
    # *vpgather* (!vsib)
    "vperm2i128_4": "rrmiy:660F3AV46rMU",
    "vpmaskmovd_3": "rrxoy:660F38V8CrM|xrroy:660F38V8ERm",
    "vpmaskmovq_3": "rrxoy:660F38VX8CrM|xrroy:660F38VX8ERm",
    "vpsllvd_3": "rrmoy:660F38V47rM",
    "vpsllvq_3": "rrmoy:660F38VX47rM",
    "vpsravd_3": "rrmoy:660F38V46rM",
    "vpsrlvd_3": "rrmoy:660F38V45rM",
    "vpsrlvq_3": "rrmoy:660F38VX45rM",

    # Intel ADX
    "adcx_2": "rmqd:660F38F6rM",
    "adox_2": "rmqd:F30F38F6rM",

    # BMI1
    "andn_3": "rrmqd:0F38VF2rM",
    "bextr_3": "rmrqd:0F38wF7rM",
    "blsi_2": "rmqd:0F38vF33m",
    "blsmsk_2": "rmqd:0F38vF32m",
    "blsr_2": "rmqd:0F38vF31m",
    "tzcnt_2": "rmqdw:F30FBCrM",

    # BMI2
    "bzhi_3": "rmrqd:0F38wF5rM",
    "mulx_3": "rrmqd:F20F38VF6rM",
    "pdep_3": "rrmqd:F20F38VF5rM",
    "pext_3": "rrmqd:F30F38VF5rM",
    "rorx_3": "rmSqd:F20F3AuF0rMS",
    "sarx_3": "rmrqd:F30F38wF7rM",
    "shrx_3": "rmrqd:F20F38wF7rM",
    "shlx_3": "rmrqd:660F38wF7rM",

    # FMA3
    "vfmaddsub132pd_3": "rrmoy:660F38VX96rM",
    "vfmaddsub132ps_3": "rrmoy:660F38V96rM",
    "vfmaddsub213pd_3": "rrmoy:660F38VXA6rM",
    "vfmaddsub213ps_3": "rrmoy:660F38VA6rM",
    "vfmaddsub231pd_3": "rrmoy:660F38VXB6rM",
    "vfmaddsub231ps_3": "rrmoy:660F38VB6rM",

    "vfmsubadd132pd_3": "rrmoy:660F38VX97rM",
    "vfmsubadd132ps_3": "rrmoy:660F38V97rM",
    "vfmsubadd213pd_3": "rrmoy:660F38VXA7rM",
    "vfmsubadd213ps_3": "rrmoy:660F38VA7rM",
    "vfmsubadd231pd_3": "rrmoy:660F38VXB7rM",
    "vfmsubadd231ps_3": "rrmoy:660F38VB7rM",

    "vfmadd132pd_3": "rrmoy:660F38VX98rM",
    "vfmadd132ps_3": "rrmoy:660F38V98rM",
    "vfmadd132sd_3": "rrro:660F38VX99rM|rrx/ooq:",
    "vfmadd132ss_3": "rrro:660F38V99rM|rrx/ood:",
    "vfmadd213pd_3": "rrmoy:660F38VXA8rM",
    "vfmadd213ps_3": "rrmoy:660F38VA8rM",
    "vfmadd213sd_3": "rrro:660F38VXA9rM|rrx/ooq:",
    "vfmadd213ss_3": "rrro:660F38VA9rM|rrx/ood:",
    "vfmadd231pd_3": "rrmoy:660F38VXB8rM",
    "vfmadd231ps_3": "rrmoy:660F38VB8rM",
    "vfmadd231sd_3": "rrro:660F38VXB9rM|rrx/ooq:",
    "vfmadd231ss_3": "rrro:660F38VB9rM|rrx/ood:",

    "vfmsub132pd_3": "rrmoy:660F38VX9ArM",
    "vfmsub132ps_3": "rrmoy:660F38V9ArM",
    "vfmsub132sd_3": "rrro:660F38VX9BrM|rrx/ooq:",
    "vfmsub132ss_3": "rrro:660F38V9BrM|rrx/ood:",
    "vfmsub213pd_3": "rrmoy:660F38VXAArM",
    "vfmsub213ps_3": "rrmoy:660F38VAArM",
    "vfmsub213sd_3": "rrro:660F38VXABrM|rrx/ooq:",
    "vfmsub213ss_3": "rrro:660F38VABrM|rrx/ood:",
    "vfmsub231pd_3": "rrmoy:660F38VXBArM",
    "vfmsub231ps_3": "rrmoy:660F38VBArM",
    "vfmsub231sd_3": "rrro:660F38VXBBrM|rrx/ooq:",
    "vfmsub231ss_3": "rrro:660F38VBBrM|rrx/ood:",

    "vfnmadd132pd_3": "rrmoy:660F38VX9CrM",
    "vfnmadd132ps_3": "rrmoy:660F38V9CrM",
    "vfnmadd132sd_3": "rrro:660F38VX9DrM|rrx/ooq:",
    "vfnmadd132ss_3": "rrro:660F38V9DrM|rrx/ood:",
    "vfnmadd213pd_3": "rrmoy:660F38VXACrM",
    "vfnmadd213ps_3": "rrmoy:660F38VACrM",
    "vfnmadd213sd_3": "rrro:660F38VXADrM|rrx/ooq:",
    "vfnmadd213ss_3": "rrro:660F38VADrM|rrx/ood:",
    "vfnmadd231pd_3": "rrmoy:660F38VXBCrM",
    "vfnmadd231ps_3": "rrmoy:660F38VBCrM",
    "vfnmadd231sd_3": "rrro:660F38VXBDrM|rrx/ooq:",
    "vfnmadd231ss_3": "rrro:660F38VBDrM|rrx/ood:",

    "vfnmsub132pd_3": "rrmoy:660F38VX9ErM",
    "vfnmsub132ps_3": "rrmoy:660F38V9ErM",
    "vfnmsub132sd_3": "rrro:660F38VX9FrM|rrx/ooq:",
    "vfnmsub132ss_3": "rrro:660F38V9FrM|rrx/ood:",
    "vfnmsub213pd_3": "rrmoy:660F38VXAErM",
    "vfnmsub213ps_3": "rrmoy:660F38VAErM",
    "vfnmsub213sd_3": "rrro:660F38VXAFrM|rrx/ooq:",
    "vfnmsub213ss_3": "rrro:660F38VAFrM|rrx/ood:",
    "vfnmsub231pd_3": "rrmoy:660F38VXBErM",
    "vfnmsub231ps_3": "rrmoy:660F38VBErM",
    "vfnmsub231sd_3": "rrro:660F38VXBFrM|rrx/ooq:",
    "vfnmsub231ss_3": "rrro:660F38VBFrM|rrx/ood:",
}


def _add_families() -> None:
    def each(table: Dict[str, int]):
        return table.items()

    # Arithmetic
    for name, n in each({"add": 0, "or": 1, "adc": 2, "sbb": 3, "and": 4, "sub": 5, "xor": 6, "cmp": 7}):
        n8 = n << 3
        OPS[f"{name}_2"] = (
            f"mr:{1+n8:02X}Rm|rm:{3+n8:02X}rM|mI1qdw:81{n:X}mI|mS1qdw:83{n:X}mS"
            f"|Ri1qdwb:{5+n8:02X}ri|mi1qdwb:81{n:X}mi"
        )

    # Shifts
    for name, n in each({"rol": 0, "ror": 1, "rcl": 2, "rcr": 3, "shl": 4, "shr": 5, "sar": 7, "sal": 4}):
        OPS[f"{name}_2"] = f"m1:D1{n:X}m|mC1qdwb:D3{n:X}m|mi:C1{n:X}mU"

    # Conditionals
    for cc, n in each(CONDITIONS):
        OPS[f"j{cc}_1"] = f"J.:n0F8{n:X}J"
        OPS[f"set{cc}_1"] = f"mb:n0F9{n:X}2m"
        OPS[f"cmov{cc}_2"] = f"rmqdw:0F4{n:X}rM"

    # x87 arithmetic
    for name, n in each({"add": 0, "mul": 1, "com": 2, "comp": 3, "sub": 4, "subr": 5, "div": 6, "divr": 7}):
        nc = 0xC0 + (n << 3)
        nr = nc + (0 if n < 4 else (8 if n % 2 == 0 else -8))
        fn = "f" + name
        OPS[f"{fn}_1"] = f"ff:D8{nc:02X}r|xd:D8{n:X}m|xq:nDC{n:X}m"
        if n in (2, 3):
            OPS[f"{fn}_2"] = f"Fff:D8{nc:02X}R|Fx2d:D8{n:X}M|Fx2q:nDC{n:X}M"
        else:
            OPS[f"{fn}_2"] = f"Fff:D8{nc:02X}R|fFf:DC{nr:02X}r|Fx2d:D8{n:X}M|Fx2q:nDC{n:X}M"
            OPS[f"{fn}p_1"] = f"ff:DE{nr:02X}r"
            OPS[f"{fn}p_2"] = f"fFf:DE{nr:02X}r"
        OPS[f"fi{name}_1"] = f"xd:DA{n:X}m|xw:nDE{n:X}m"

    # x87 conditional moves
    for cc, n in each({"b": 0, "e": 1, "be": 2, "u": 3, "nb": 4, "ne": 5, "nbe": 6, "nu": 7}):
        nc = 0xDAC0 + ((n & 3) << 3) + ((n & 4) << 6)
        OPS[f"fcmov{cc}_1"] = f"ff:{nc:04X}r"
        OPS[f"fcmov{cc}_2"] = f"Fff:{nc:04X}R"

    # SSE / AVX floating point arithmetic
    for name, n in each({"sqrt": 1, "add": 8, "mul": 9, "sub": 12, "min": 13, "div": 14, "max": 15}):
        OPS[f"{name}ps_2"] = f"rmo:0F5{n:X}rM"
        OPS[f"{name}ss_2"] = f"rro:F30F5{n:X}rM|rx/od:"
        OPS[f"{name}pd_2"] = f"rmo:660F5{n:X}rM"
        OPS[f"{name}sd_2"] = f"rro:F20F5{n:X}rM|rx/oq:"
        if n != 1:
            OPS[f"v{name}ps_3"] = f"rrmoy:0FV5{n:X}rM"
            OPS[f"v{name}ss_3"] = f"rrro:F30FV5{n:X}rM|rrx/ood:"
            OPS[f"v{name}pd_3"] = f"rrmoy:660FV5{n:X}rM"
            OPS[f"v{name}sd_3"] = f"rrro:F20FV5{n:X}rM|rrx/ooq:"

    # SSE2 / AVX / AVX2 integer arithmetic (66 0F leaf)
    for name, n in each({
        "paddb": 0xFC, "paddw": 0xFD, "paddd": 0xFE, "paddq": 0xD4,
        "paddsb": 0xEC, "paddsw": 0xED, "packssdw": 0x6B,
        "packsswb": 0x63, "packuswb": 0x67, "paddusb": 0xDC,
        "paddusw": 0xDD, "pand": 0xDB, "pandn": 0xDF, "pavgb": 0xE0,
        "pavgw": 0xE3, "pcmpeqb": 0x74, "pcmpeqd": 0x76,
        "pcmpeqw": 0x75, "pcmpgtb": 0x64, "pcmpgtd": 0x66,
        "pcmpgtw": 0x65, "pmaddwd": 0xF5, "pmaxsw": 0xEE,
        "pmaxub": 0xDE, "pminsw": 0xEA, "pminub": 0xDA,
        "pmulhuw": 0xE4, "pmulhw": 0xE5, "pmullw": 0xD5,
        "pmuludq": 0xF4, "por": 0xEB, "psadbw": 0xF6, "psubb": 0xF8,
        "psubw": 0xF9, "psubd": 0xFA, "psubq": 0xFB, "psubsb": 0xE8,
        "psubsw": 0xE9, "psubusb": 0xD8, "psubusw": 0xD9,
        "punpckhbw": 0x68, "punpckhwd": 0x69, "punpckhdq": 0x6A,
        "punpckhqdq": 0x6D, "punpcklbw": 0x60, "punpcklwd": 0x61,
        "punpckldq": 0x62, "punpcklqdq": 0x6C, "pxor": 0xEF,
    }):
        OPS[f"{name}_2"] = f"rmo:660F{n:02X}rM"
        OPS[f"v{name}_3"] = f"rrmoy:660FV{n:02X}rM"


CONDITIONS: Dict[str, int] = {
    "o": 0, "no": 1, "b": 2, "nb": 3, "e": 4, "ne": 5, "be": 6, "nbe": 7,
    "s": 8, "ns": 9, "p": 10, "np": 11, "l": 12, "nl": 13, "le": 14, "nle": 15,
    "c": 2, "nae": 2, "nc": 3, "ae": 3, "z": 4, "nz": 5, "na": 6, "a": 7,
    "pe": 10, "po": 11, "nge": 12, "ge": 13, "ng": 14, "g": 15,
}

_add_families()
