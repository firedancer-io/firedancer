/**
 * @name Footprint bounding
 * @description A type does not fit in its defined footprint.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/footprint-bounding
 */

import cpp
import filter

class FootprintMacro extends Macro {
  FootprintMacro() {
    this.hasName([
      "FD_FSEQ_FOOTPRINT",
      "FD_BLAKE3_FOOTPRINT",
      "FD_SIPHASH13_FOOTPRINT",
      "FD_KEYGUARD_CLIENT_FOOTPRINT",
      "FD_WKSP_PRIVATE_PINFO_FOOTPRINT",
      "FD_FRAG_META_FOOTPRINT"
    ])
  }

  string getTypeName() {
    this.hasName("FD_FSEQ_FOOTPRINT") and result = "fd_fseq_shmem"
    or
    this.hasName("FD_BLAKE3_FOOTPRINT") and result = "fd_blake3"
    or
    this.hasName("FD_SIPHASH13_FOOTPRINT") and result = "fd_siphash13_private"
    or
    this.hasName("FD_KEYGUARD_CLIENT_FOOTPRINT") and result = "fd_keyguard_client"
    or
    this.hasName("FD_WKSP_PRIVATE_PINFO_FOOTPRINT") and result = "fd_wksp_private_pinfo"
    or
    this.hasName("FD_FRAG_META_FOOTPRINT") and result = "fd_frag_meta"
  }

  int getFootprint() { result = this.getAnInvocation().getExpr().getValue().toInt() }
}

from Class type, FootprintMacro footprint, int size
where
  included(type.getLocation()) and
  included(footprint.getLocation()) and
  type.getName() = footprint.getTypeName() and
  size = footprint.getFootprint() and
  type.getSize() > size
select type,
  "The type $@ has size " + type.getSize().toString() +
    " bytes, exceeding $@ (" + size.toString() + " bytes).",
  type, type.getName(), footprint, footprint.getName()
