/**
 * @name Footprint bounding
 * @description A struct does not fit in the defined footprint.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/footprint-bounding
 */

import cpp
import filter


predicate fitsInFootprint(string structName, string macroName) {
    exists(Struct struct |
        struct.getName() = structName and
        included(struct.getLocation()) and
        exists(MacroInvocation footprint |
            footprint.getMacroName() = macroName and
            footprint.getExpr().toString().toInt() >= struct.getSize()
        )
    )
}

from string macroName, string structName
where (
    macroName = "FD_FUNK_FOOTPRINT" and
    structName = "fd_funk_private" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_FSEQ_FOOTPRINT" and
    structName = "fd_fseq_shmem_t" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_FUNK_TXN_FOOTPRINT" and
    structName = "fd_funk_txn_private" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_BLAKE3_FOOTPRINT" and
    structName = "fd_blake3_private" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_SIPHASH13_FOOTPRINT" and
    structName = "fd_blake3_private" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_KEYGUARD_CLIENT_FOOTPRINT" and
    structName = "fd_keyguard_client" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_SHREDCAP_MANIFEST_CAP_FOOTPRINT_V1" and
    structName = "fd_shredcap_manifest_cap_V1" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_FUNK_TXN_XID_FOOTPRINT" and
    structName = "fd_funk_txn_xid" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_FUNK_XID_KEY_PAIR_FOOTPRINT" and
    structName = "fd_funk_xid_key_pair" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_WKSP_PRIVATE_PINFO_FOOTPRINT" and
    structName = "fd_wksp_private_pinfo" and
    not fitsInFootprint(structName, macroName)
) and (
    macroName = "FD_FRAG_META_FOOTPRINT" and
    structName = "fd_frag_meta" and
    not fitsInFootprint(structName, macroName)
)
select structName, structName + "does not fit in " + macroName