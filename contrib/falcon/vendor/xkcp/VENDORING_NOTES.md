# XKCP vendoring notes

Source: `https://github.com/XKCP/XKCP` (master branch, no tag).
Cloned shallow and committed without modifying the library code under
`lib/`.

The following directories from the upstream tree are **not** vendored
because they are not required to build the static libraries we link
against (`generic64/libXKCP.a` and `AVX512/libXKCP.a`):

- `CI/`            (continuous-integration scripts)
- `Standalone/`    (standalone demo implementations)
- `doc/`           (documentation, except for one stub described below)
- `tests/`         (XKCP's unit-test sources, except for two stubs)
- `util/`          (the `KeccakSum` command-line utility)
- `.github/`, `.gitmodules`, `.travis.yml`, `README.markdown`,
  `usage-example.md`

The `support/XKCBuild/` submodule **is** vendored verbatim (it is what
expands `Makefile.build` via `xsltproc` and is required for any build).

XKCP's `Makefile.build` references three files in the stripped-out
directories via XInclude:

- `tests/SUPERCOP/SUPERCOP.build`
- `tests/NIST_LWC/NIST_LWC.build`
- `doc/HOWTO-customize.build`

To keep the build working without the corresponding sources, we ship
empty XML stubs at those paths.  No upstream build target is altered;
only the unrelated SUPERCOP / NIST-LWC / HOWTO targets become absent
from the expanded target list.
