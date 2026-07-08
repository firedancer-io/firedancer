# Vendored in-tree (src/third_party/s2n-bignum)
FD_HAS_S2NBIGNUM:=1
CFLAGS+=-DFD_HAS_S2NBIGNUM=1
CPPFLAGS+=-isystem src/third_party/s2n-bignum/include
