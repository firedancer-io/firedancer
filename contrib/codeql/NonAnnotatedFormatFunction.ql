/**
 * Find calls to functions that likely expect a format string but are not annotated as such.
 * @id asymmetric-research/non-annotated-format-function
 * @kind problem
 * @severity warning
 */

import cpp

from StringLiteral s, Function f
where s.getValueText().regexpMatch(".*%[A-z0-9$].*") and
s.getParent().(FunctionCall).getTarget() = f and  /* ignores dynamic function calls */
not exists( Attribute attr | attr = f.getAnAttribute() | attr.getName() = "format" ) and
f.getLocation().getFile().getRelativePath().regexpMatch("src/.*")
select f, "Likely format string passed to non-format function"
