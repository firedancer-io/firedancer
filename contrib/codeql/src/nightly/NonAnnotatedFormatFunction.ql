/**
 * Find calls to functions that likely expect a format string but are not annotated as such.
 *
 * @id asymmetric-research/non-annotated-format-function
 * @kind problem
 * @severity warning
 */

import cpp
import filter

from StringLiteral s, FunctionCall fc, Function f
where
  included(fc.getLocation()) and
  f = fc.getTarget() and
  s.getValueText().regexpMatch(".*%[A-z0-9$].*") and
  s.getParent() = fc and
  /* ignores dynamic function calls */
  not exists(Attribute attr | attr = f.getAnAttribute() | attr.getName() = "format") and
  f.getLocation().getFile().getRelativePath().regexpMatch("src/.*")
select fc, "Likely format string passed to $@.", f, "non-format function"
