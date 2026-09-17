This directory contains a subset of the blst library at
https://github.com/supranational/blst

Files are copied exactly from tag v0.3.13, with no Firedancer
specific modifications.  Do not edit vendored files locally; update
by re-running `vendor.sh` against a new pinned tag.

Upstream build.sh compiles exactly two objects: src/server.c (a
unity build #including every other .c except the optional
client_min_pk.c / client_min_sig.c min-pk/min-sig API variants and
the opt-in pentaroot.c (BLST_FR_PENTAROOT) module, none of which
are imported) and build/assembly.S (which #includes the
pre-generated per-arch .s bodies from build/elf/ at preprocess
time).  The src/asm/*.pl perlasm generators that produce build/elf/
are not imported; the checked-in .s files are upstream's own
pre-generated output, the same ones build.sh consumes.

Firedancer compiles assembly.S as is, but in place of server.c it
compiles two unity TUs of its own, fd_blst_curve.c and
fd_blst_field.c, which #include the same src/*.c files (server.c
stays vendored, unused).  point.h and fields.h forward-declare the
point, sqrt/recip and fp12 helpers static, so every file calling them
shares fd_blst_curve.c; keygen.c, exports.c and rb_tree.c only need
reciprocal_fr, which fd_blst_field.c defines via the identical export
blst_fr_inverse.  bulk_addition.c and multi_scalar.c (blst_p1s_* /
blst_p2s_*: batch addition and Pippenger multi-scalar multiplication)
are not compiled: nothing in Firedancer uses them.  A new use fails at
link time; add both files to fd_blst_curve.c.  When re-vendoring, diff
the new server.c against the two include lists.
