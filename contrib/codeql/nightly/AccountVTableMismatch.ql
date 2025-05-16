/**
 * @name Account v-table mismatch
 * @description Detects mismatches between the account dereferenced to get the v-table and the account passed as an argument.
 * Essentially, cases where X->vt->foo(Y) and X!=Y, to detect variants of https://github.com/firedancer-io/firedancer/pull/5124
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/account-vtable-mismatch
 */

import cpp

from PointerFieldAccess vt, VariableCall vc
where vt.getTarget().hasName("vt") and
vc.getExpr().(PointerFieldAccess).getQualifier() = vt and
vc.getArgument(0).toString() != vt.getQualifier().toString() and
vt.getUnspecifiedType().stripType().hasName("fd_txn_account_vtable")
select vc, "Dereferenced account does not match the account being modified"
