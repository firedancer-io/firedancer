/**
 * @name Tile Union Type Confusion
 * @description A tile union member is accessed in a tile source file
                that does not correspond to the union member type.
                This is likely a bug.
 * @kind problem
 * @id asymmetric-research/tile-union-mismatch
 * @problem.severity warning
 * @precision medium
 */

import cpp

class TileUnionVariant extends Declaration {
  TileUnionVariant() {
    /* unnamed unions are missing some crucial information
     * in the CodeQL DB, so we do this, which is good enough */
    exists(Union s | s.getAMember() = this |
      s.getLocation().getFile().getBaseName() = "fd_topo.h" and
      s.getAMember().hasName("shred")
    )
  }
}

class TileAccessInTile extends FieldAccess {
  TileAccessInTile() {
    this.getLocation().getFile().getBaseName().matches("%_tile.%") and
    this.getTarget() instanceof TileUnionVariant
  }
}

from TileAccessInTile t, string tileName
where
  tileName = t.getLocation().getFile().getBaseName() and
  not tileName.matches("%_" + t.toString() + "_%") and
  /* net "inheritance" case */
  not t.toString() = "net"
select t, t.getLocation().getFile().getBaseName()
