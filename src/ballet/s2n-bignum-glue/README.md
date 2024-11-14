s2n-bignum-glue wires up the s2n-bignum Makefile with the Firedancer build system.

The Local.mk fragment adds all s2n-bignum fragments to libfd_ballet.a and sets up CPPFLAGS.

In order to do so, Firedancer must be aware of the list of object files provided by s2n-bignum.
These are defined in `glue.mk`.

Any time the s2n-bignum submodule is updated, run

```
make -C src/ballet/s2n-bignum-glue
```
