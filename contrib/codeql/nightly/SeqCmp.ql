/**
 * Finds relational comparisons of sequence numbers that are not using the fd_seq_* functions
 * @id asymmetric-research/seq-cmp
 * @kind problem
 * @severity warning
 * @precision low
 */

import cpp

predicate include(Location l) {
    l.getFile().getRelativePath().matches("src/")
    or not l.getFile().getBaseName().matches("fd_cstr%")
}

class SeqNum extends Variable {
    SeqNum() {
        this.getName().matches("%seq%") and
        include(this.getLocation())
    }
}

from SeqNum seqNum1, SeqNum seqNum2, Access a, Access b
where exists(
    /* Using == and != is fine because they match the implementation of
     fd_seq_eq and fd_seq_ne */
    RelationalOperation cmp |
    cmp.getAnOperand() = a and
    cmp.getAnOperand() = b
) and
a = seqNum1.getAnAccess() and
b = seqNum2.getAnAccess() and
a != b and
include(a.getLocation()) and
include(b.getLocation()) and
a.getTarget().getName() < b.getTarget().getName() /* Avoid duplicate results */
select a, "Use fd_seq_lt, fd_seq_le, fd_seq_ge, fd_seq_gt or equivlanet implementations to compare sequence numbers"