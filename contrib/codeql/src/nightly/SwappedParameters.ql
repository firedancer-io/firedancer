/**
 * @name Swapped Parameters
 * @description Detects cases where the parameters of a function are
 * swapped between the function definition and the function
 * implementation. If the both parameters are the same type and have the
 * the compiler will not warn about it, but this confusion can easily
 * lead to bugs.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/swapped-parameters
 */

import cpp
import filter

from Function f, ParameterDeclarationEntry defP, Parameter implP
where included(f.getLocation()) and
implP = f.getAParameter() and
defP = f.getADeclarationEntry().getAParameterDeclarationEntry() and
defP.getName() = implP.getName() and
defP.getIndex() != implP.getIndex()
select defP, "Parameter " + defP.getName() + " is swapped with parameter " + implP.getName() + " in function " + f.getName() + "."