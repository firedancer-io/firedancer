import cpp

/**
 * Models the `fd_topo_run_tile_t` type.
 */
class FdTopoRunTileType extends Type {
  FdTopoRunTileType() { this.getName() = "fd_topo_run_tile_t" }
}

/**
 * A global variable of type `fd_topo_run_tile_t`.
 */
class FdTopoRunTileVariable extends GlobalVariable {
  FdTopoRunTileVariable() { this.getType() instanceof FdTopoRunTileType }

  /**
   * Gets the aggregate initializer expression for the given field, if any.
   */
  Expr getAFieldExpr(string fieldName) {
    exists(Field f |
      f.hasName(fieldName) and
      result = this.getInitializer().getExpr().(ClassAggregateLiteral).getAFieldExpr(f)
    )
  }

  /**
   * Gets the tile name from the `name` field.
   */
  string getTileName() { result = this.getAFieldExpr("name").(StringLiteral).getValue() }
}
