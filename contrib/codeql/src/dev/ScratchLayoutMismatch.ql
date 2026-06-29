/**
 * @name Scratch layout mismatch
 * @description The FD_{LAYOUT,SCRATCH}_{APPEND,INIT,FINI} macros are prone to mismatches. This
 * query can find some of them. This is a syntactic comparison.
 * @id asymmetric-research/scratch-layout-mismatch
 * @kind problem
 * @precision low
 * @problem.severity warning
 */

import cpp
import filter

class LayoutOption extends MacroInvocation {
  LayoutOption() { this.getMacroName() = ["FD_LAYOUT_APPEND", "FD_LAYOUT_INIT", "FD_LAYOUT_FINI"] }

  LayoutOption getAbove() {
    result.getLocation().getEndLine() < this.getLocation().getEndLine() and
    result.getLocation().getFile() = this.getLocation().getFile() and
    not exists(
      LayoutOption other |
        other.getLocation().getEndLine() < this.getLocation().getEndLine() and
        other.getLocation().getEndLine() > result.getLocation().getEndLine() and
        other != result and
        other.getLocation().getFile() = this.getLocation().getFile()
    ) and
    result.getMacroName() != "FD_LAYOUT_FINI"
  }

  LayoutOption getBelow() {
    result.getLocation().getEndLine() > this.getLocation().getEndLine() and
    result.getLocation().getFile() = this.getLocation().getFile() and
    not exists(
      LayoutOption other |
        other.getLocation().getEndLine() > this.getLocation().getEndLine() and
        other.getLocation().getEndLine() < result.getLocation().getEndLine() and
        other != result and
        other.getLocation().getFile() = this.getLocation().getFile()
    ) and
    result.getMacroName() != "FD_LAYOUT_INIT"
  }

  private predicate syntaxCompare(LayoutOption other, int argIndex) {
    this.getExpandedArgument(argIndex).replaceAll(" ", "") = other.getExpandedArgument(argIndex).replaceAll(" ", "")
  }

  predicate matches(ScratchOption other) {
    (
    other.getMacroName() = "FD_SCRATCH_ALLOC_APPEND" and
    this.getMacroName() = "FD_LAYOUT_APPEND" and
    this.syntaxCompare(other, 1) and
    this.syntaxCompare(other, 2)
    )
    or
    (
    other.getMacroName() = "FD_SCRATCH_ALLOC_INIT" and
    this.getMacroName() = "FD_LAYOUT_INIT"
    )
    or
    (
    other.getMacroName() = "FD_SCRATCH_ALLOC_FINI" and
    this.getMacroName() = "FD_LAYOUT_FINI" and
    this.syntaxCompare(other, 1)
    )
  }
}


class ScratchOption extends MacroInvocation {
  ScratchOption() {
    this.getMacroName() = ["FD_SCRATCH_ALLOC_APPEND",
                           "FD_SCRATCH_ALLOC_INIT",
                           "FD_SCRATCH_ALLOC_FINI"] and
    included(this.getLocation())
  }

  LayoutOption getAbove() {
    result.getLocation().getEndLine() < this.getLocation().getEndLine() and
    result.getLocation().getFile() = this.getLocation().getFile() and
    not exists(
      LayoutOption other |
        other.getLocation().getEndLine() < this.getLocation().getEndLine() and
        other.getLocation().getEndLine() > result.getLocation().getEndLine() and
        other != result and
        other.getLocation().getFile() = this.getLocation().getFile()
    ) and
    result.getMacroName() != "FD_SCRATCH_ALLOC_FINI"
  }

  LayoutOption getBelow() {
    result.getLocation().getEndLine() > this.getLocation().getEndLine() and
    result.getLocation().getFile() = this.getLocation().getFile() and
    not exists(
      LayoutOption other |
        other.getLocation().getEndLine() > this.getLocation().getEndLine() and
        other.getLocation().getEndLine() < result.getLocation().getEndLine() and
        other != result and
        other.getLocation().getFile() = this.getLocation().getFile()
    ) and
    result.getMacroName() != "FD_SCRATCH_ALLOC_INIT"
  }

}

from ScratchOption scratch
where
  not exists(LayoutOption layout |
    layout.matches(scratch) and
    (layout.getAbove().matches(scratch.getAbove()) or not exists(ScratchOption above | above = scratch.getAbove())) and
    (layout.getBelow().matches(scratch.getBelow()) or not exists(ScratchOption below | below = scratch.getBelow()))
  )
select scratch, "FD_SCRATCH_ALLOC_* does not match FD_LAYOUT_*"
