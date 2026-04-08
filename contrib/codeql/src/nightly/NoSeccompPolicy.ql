/**
 * @name No seccomp policy is defined for this tile.
 * @description Finds tiles that don't include a seccomp policy for their tile. This is usually not intentional.
 * @kind problem
 * @severity warning
 * @id asymmetric-research/no-seccomp-policy
 * @tags correctness
 */

import cpp

/** Models the fd_topo_run_tile_t type. */
private class FdTopoRunTileType extends Type {
  FdTopoRunTileType() { this.getName() = "fd_topo_run_tile_t" }
}

Field populateAllowedSeccompField() { result.hasName("populate_allowed_seccomp") }

private class FdTopoRunTileVariable extends GlobalVariable {
  FdTopoRunTileVariable() { this.getType() instanceof FdTopoRunTileType }
}

predicate usesSeccompPolicy(FdTopoRunTileVariable tileVar) {
  exists(Function populateAllowedSeccompPolicyFunction |
    tileVar
        .getInitializer()
        .getExpr()
        .(ClassAggregateLiteral)
        .getAFieldExpr(populateAllowedSeccompField())
        .(FunctionAccess)
        .getTarget() = populateAllowedSeccompPolicyFunction
  |
    exists(Function expectedSeccompPolicyFunction |
      expectedSeccompPolicyFunction.getName().matches("populate_sock_filter_policy_%") and
      (
        alwaysCalls(populateAllowedSeccompPolicyFunction, expectedSeccompPolicyFunction)
        or
        exists(Function otherFunction |
          alwaysCalls(populateAllowedSeccompPolicyFunction, otherFunction) and
          alwaysCalls(otherFunction, expectedSeccompPolicyFunction)
        )
      )
    )
  )
}

/** Holds if `caller` always calls `callee`. */
predicate alwaysCalls(Function caller, Function callee) {
  postDominates(callee.getACallToThisFunction(), caller.getEntryPoint())
}

predicate isRelevantTile(FdTopoRunTileVariable tileVar) {
  not tileVar.getLocation().getFile().getBaseName().matches("fd_bench%.c") and
  not tileVar.getLocation().getFile().getBaseName() = "fd_backtest_tile.c" and
  not tileVar.getLocation().getFile().getAbsolutePath().matches("%/src/app/shared_dev/%") and
  not tileVar.getLocation().getFile().getAbsolutePath().matches("%/src/discoh/%")
}

from FdTopoRunTileVariable tileVar
where
  not usesSeccompPolicy(tileVar) and
  isRelevantTile(tileVar)
select tileVar,
  "This tile does not use a seccomp policy or does not ALWAYS call a function to populate one."
