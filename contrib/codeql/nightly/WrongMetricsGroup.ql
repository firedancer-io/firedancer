/**
 * @name Wrong metrics group in tile
 * @description Metrics accessed in a tile should belong to that tile
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id asymmetric-research/metrics-wrong-group
 */

import cpp


class Tile extends File {
  Tile() { this.getBaseName().matches("%_tile.%") }

  string getName() {
    exists(GlobalVariable v | v.getType().getName() = "fd_topo_run_tile_t" |
      v.getLocation().getFile() = this.getFile() and
      exists(Field f | f.hasName("name") |
        v.getInitializer()
            .getExpr()
            .(ClassAggregateLiteral)
            .getAFieldExpr(f)
            .(StringLiteral)
            .getValue() = result
      )
    )
  }
}

from ArrayExpr arrayAccess, MacroAccess ma, Tile t, string metricsGroup
where
  arrayAccess.getArrayBase().toString() = "fd_metrics_tl" and
  inmacroexpansion(arrayAccess.getArrayOffset(), ma) and
  ma.getMacroName().matches("FD_METRICS_%") and
  arrayAccess.getFile() = t.getLocation().getFile() and
  metricsGroup = ma.getMacroName().splitAt("_", 3) and
  metricsGroup.toLowerCase() != t.getName()
select arrayAccess, "Metrics group " + metricsGroup + " unexpected for tile " + t.getName()
