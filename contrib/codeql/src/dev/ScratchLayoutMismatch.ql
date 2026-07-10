/**
 * @name Scratch layout mismatch
 * @description Finds reordered or incompatible FD_SCRATCH_ALLOC_* alignment sequences relative
 * to a plausible FD_LAYOUT_* sequence in the same source component.
 * @id asymmetric-research/scratch-layout-mismatch
 * @kind problem
 * @precision medium
 * @problem.severity warning
 */

import cpp
import filter

private string sourceFamily(File file) {
  result = file.getStem().regexpReplaceAll("(_private|_internal|_impl)$", "")
}

private predicate relatedSourceFiles(File layoutFile, File scratchFile) {
  /* Layout helpers commonly live in a .h while allocation lives in the matching .c or _private file. */
  layoutFile.getParentContainer() = scratchFile.getParentContainer() and
  sourceFamily(layoutFile) = sourceFamily(scratchFile)
}

class LayoutOption extends MacroInvocation {
  LayoutOption() { this.getMacroName() = ["FD_LAYOUT_APPEND", "FD_LAYOUT_INIT", "FD_LAYOUT_FINI"] }
}

class ScratchOption extends MacroInvocation {
  ScratchOption() {
    this.getMacroName() =
      [
        "FD_SCRATCH_ALLOC_APPEND",
        "FD_SCRATCH_ALLOC_INIT",
        "FD_SCRATCH_ALLOC_FINI"
      ] and
    included(this.getLocation())
  }
}

private string normalizedArgument(MacroInvocation invocation, int index) {
  result = invocation.getExpandedArgument(index).regexpReplaceAll("\\s", "")
}

/** A deduplicated layout option, keyed by its actual source position. */
private predicate layoutOption(
  File file, int line, int column, string kind, string alignment, string size
) {
  exists(LayoutOption option |
    file = option.getActualLocation().getFile() and
    line = option.getActualLocation().getEndLine() and
    column = option.getActualLocation().getEndColumn() and
    kind = option.getMacroName() and
    (
      kind = "FD_LAYOUT_INIT" and alignment = "" and size = ""
      or
      kind = "FD_LAYOUT_APPEND" and
      alignment = normalizedArgument(option, 1) and
      size = normalizedArgument(option, 2)
      or
      kind = "FD_LAYOUT_FINI" and
      alignment = normalizedArgument(option, 1) and
      size = ""
    )
  )
}

/** A deduplicated scratch option, keyed by its actual source position. */
private predicate scratchOption(
  File file, int line, int column, string kind, string alignment, string size
) {
  exists(ScratchOption option |
    file = option.getActualLocation().getFile() and
    line = option.getActualLocation().getEndLine() and
    column = option.getActualLocation().getEndColumn() and
    kind = option.getMacroName() and
    (
      kind = "FD_SCRATCH_ALLOC_INIT" and alignment = "" and size = ""
      or
      kind = "FD_SCRATCH_ALLOC_APPEND" and
      alignment = normalizedArgument(option, 1) and
      size = normalizedArgument(option, 2)
      or
      kind = "FD_SCRATCH_ALLOC_FINI" and
      alignment = normalizedArgument(option, 1) and
      size = ""
    )
  )
}

bindingset[earlierLine, earlierColumn, laterLine, laterColumn]
private predicate positionBefore(int earlierLine, int earlierColumn, int laterLine, int laterColumn) {
  (
    earlierLine < laterLine
    or
    earlierLine = laterLine and earlierColumn < laterColumn
  )
}

bindingset[alignment]
private string comparableAlignment(string alignment) {
  result = alignment.regexpReplaceAll("_Alignof\\((fd_[A-Za-z0-9_]+)_t\\)", "$1_align()")
}

bindingset[alignment]
private int alignmentValue(string alignment) {
  alignment.regexpMatch("\\(*[0-9]+(UL|LU|U|L)*\\)*") and
  result = alignment.regexpReplaceAll("[^0-9]", "").toInt()
  or
  exists(Type type |
    alignment = "_Alignof(" + type.toString().regexpReplaceAll("\\s", "") + ")" and
    result = type.getAlignment()
  )
  or
  exists(Function function, ReturnStmt return |
    function.getName().matches("fd_%_align") and
    alignment = function.getName() + "()" and
    return.getEnclosingFunction() = function and
    result = return.getExpr().getValue().toInt()
  )
}

bindingset[first, second]
private predicate alignmentsMatch(string first, string second) {
  comparableAlignment(first) = comparableAlignment(second)
  or
  alignmentValue(first) = alignmentValue(second)
}

private predicate layoutInSequence(
  File file, int initLine, int initColumn, int line, int column, string kind, string alignment,
  string size
) {
  layoutOption(file, initLine, initColumn, "FD_LAYOUT_INIT", "", "") and
  layoutOption(file, line, column, kind, alignment, size) and
  not (kind = "FD_LAYOUT_INIT" and positionBefore(initLine, initColumn, line, column)) and
  (
    initLine = line and initColumn = column
    or
    positionBefore(initLine, initColumn, line, column)
  ) and
  not exists(int boundaryLine, int boundaryColumn, string boundaryKind, string a, string s |
    layoutOption(file, boundaryLine, boundaryColumn, boundaryKind, a, s) and
    boundaryKind = ["FD_LAYOUT_INIT", "FD_LAYOUT_FINI"] and
    positionBefore(initLine, initColumn, boundaryLine, boundaryColumn) and
    positionBefore(boundaryLine, boundaryColumn, line, column)
  )
}

private predicate scratchInSequence(
  File file, int initLine, int initColumn, int line, int column, string kind, string alignment,
  string size
) {
  scratchOption(file, initLine, initColumn, "FD_SCRATCH_ALLOC_INIT", "", "") and
  scratchOption(file, line, column, kind, alignment, size) and
  not (
    kind = "FD_SCRATCH_ALLOC_INIT" and
    positionBefore(initLine, initColumn, line, column)
  ) and
  (
    initLine = line and initColumn = column
    or
    positionBefore(initLine, initColumn, line, column)
  ) and
  not exists(int boundaryLine, int boundaryColumn, string boundaryKind, string a, string s |
    scratchOption(file, boundaryLine, boundaryColumn, boundaryKind, a, s) and
    boundaryKind = ["FD_SCRATCH_ALLOC_INIT", "FD_SCRATCH_ALLOC_FINI"] and
    positionBefore(initLine, initColumn, boundaryLine, boundaryColumn) and
    positionBefore(boundaryLine, boundaryColumn, line, column)
  )
}

bindingset[layoutKind, layoutAlignment, scratchKind, scratchAlignment]
private predicate optionsMatch(
  string layoutKind, string layoutAlignment, string scratchKind, string scratchAlignment
) {
  (
    layoutKind = "FD_LAYOUT_INIT" and scratchKind = "FD_SCRATCH_ALLOC_INIT"
    or
    layoutKind = "FD_LAYOUT_APPEND" and
    scratchKind = "FD_SCRATCH_ALLOC_APPEND" and
    alignmentsMatch(layoutAlignment, scratchAlignment)
    or
    layoutKind = "FD_LAYOUT_FINI" and scratchKind = "FD_SCRATCH_ALLOC_FINI"
  )
}

bindingset[firstKind, firstAlignment, secondKind, secondAlignment]
private predicate equivalentScratchOptions(
  string firstKind, string firstAlignment, string secondKind, string secondAlignment
) {
  /* A layout may aggregate a repeated region that scratch allocates one element at a time. */
  firstKind = secondKind and
  (
    firstKind = ["FD_SCRATCH_ALLOC_INIT", "FD_SCRATCH_ALLOC_FINI"]
    or
    firstKind = "FD_SCRATCH_ALLOC_APPEND" and
    alignmentsMatch(firstAlignment, secondAlignment)
  )
}

bindingset[file, initLine, initColumn, line, column]
private predicate scratchPredecessor(
  File file, int initLine, int initColumn, int line, int column, int predecessorLine,
  int predecessorColumn
) {
  exists(string kind, string alignment, string size |
    scratchInSequence(file, initLine, initColumn, predecessorLine, predecessorColumn, kind,
      alignment, size)
  ) and
  positionBefore(predecessorLine, predecessorColumn, line, column) and
  not exists(int middleLine, int middleColumn, string kind, string alignment, string size |
    scratchInSequence(file, initLine, initColumn, middleLine, middleColumn, kind, alignment, size) and
    positionBefore(predecessorLine, predecessorColumn, middleLine, middleColumn) and
    positionBefore(middleLine, middleColumn, line, column)
  )
}

bindingset[file, initLine, initColumn, line, column]
private predicate scratchSuccessor(
  File file, int initLine, int initColumn, int line, int column, int successorLine,
  int successorColumn
) {
  exists(string kind, string alignment, string size |
    scratchInSequence(file, initLine, initColumn, successorLine, successorColumn, kind, alignment,
      size)
  ) and
  positionBefore(line, column, successorLine, successorColumn) and
  not exists(int middleLine, int middleColumn, string kind, string alignment, string size |
    scratchInSequence(file, initLine, initColumn, middleLine, middleColumn, kind, alignment, size) and
    positionBefore(line, column, middleLine, middleColumn) and
    positionBefore(middleLine, middleColumn, successorLine, successorColumn)
  )
}

bindingset[scratchFile, scratchInitLine, scratchInitColumn, layoutFile, layoutInitLine,
  layoutInitColumn, scratchLine, scratchColumn, scratchKind, scratchAlignment]
private predicate orderedOptionMatch(
  File scratchFile, int scratchInitLine, int scratchInitColumn, File layoutFile, int layoutInitLine,
  int layoutInitColumn, int scratchLine, int scratchColumn, string scratchKind,
  string scratchAlignment
) {
  exists(
    int layoutLine, int layoutColumn, string layoutKind, string layoutAlignment, string layoutSize
  |
    layoutInSequence(layoutFile, layoutInitLine, layoutInitColumn, layoutLine, layoutColumn,
      layoutKind, layoutAlignment, layoutSize) and
    optionsMatch(layoutKind, layoutAlignment, scratchKind, scratchAlignment) and
    (
      not exists(int predecessorLine, int predecessorColumn |
        scratchPredecessor(scratchFile, scratchInitLine, scratchInitColumn, scratchLine,
          scratchColumn, predecessorLine, predecessorColumn)
      )
      or
      exists(
        int predecessorLine, int predecessorColumn, string predecessorKind,
        string predecessorAlignment, string predecessorSize
      |
        scratchPredecessor(scratchFile, scratchInitLine, scratchInitColumn, scratchLine,
          scratchColumn, predecessorLine, predecessorColumn) and
        scratchOption(scratchFile, predecessorLine, predecessorColumn, predecessorKind,
          predecessorAlignment, predecessorSize) and
        equivalentScratchOptions(predecessorKind, predecessorAlignment, scratchKind,
          scratchAlignment)
      )
      or
      exists(
        int predecessorLine, int predecessorColumn, string predecessorKind,
        string predecessorAlignment, string predecessorSize, int layoutPredecessorLine,
        int layoutPredecessorColumn, string layoutPredecessorKind,
        string layoutPredecessorAlignment, string layoutPredecessorSize
      |
        scratchPredecessor(scratchFile, scratchInitLine, scratchInitColumn, scratchLine,
          scratchColumn, predecessorLine, predecessorColumn) and
        scratchOption(scratchFile, predecessorLine, predecessorColumn, predecessorKind,
          predecessorAlignment, predecessorSize) and
        layoutInSequence(layoutFile, layoutInitLine, layoutInitColumn, layoutPredecessorLine,
          layoutPredecessorColumn, layoutPredecessorKind, layoutPredecessorAlignment,
          layoutPredecessorSize) and
        positionBefore(layoutPredecessorLine, layoutPredecessorColumn, layoutLine, layoutColumn) and
        optionsMatch(layoutPredecessorKind, layoutPredecessorAlignment, predecessorKind,
          predecessorAlignment)
      )
    ) and
    (
      not exists(int successorLine, int successorColumn |
        scratchSuccessor(scratchFile, scratchInitLine, scratchInitColumn, scratchLine,
          scratchColumn, successorLine, successorColumn)
      )
      or
      exists(
        int successorLine, int successorColumn, string successorKind, string successorAlignment,
        string successorSize
      |
        scratchSuccessor(scratchFile, scratchInitLine, scratchInitColumn, scratchLine,
          scratchColumn, successorLine, successorColumn) and
        scratchOption(scratchFile, successorLine, successorColumn, successorKind,
          successorAlignment, successorSize) and
        equivalentScratchOptions(scratchKind, scratchAlignment, successorKind, successorAlignment)
      )
      or
      exists(
        int successorLine, int successorColumn, string successorKind, string successorAlignment,
        string successorSize, int layoutSuccessorLine, int layoutSuccessorColumn,
        string layoutSuccessorKind, string layoutSuccessorAlignment, string layoutSuccessorSize
      |
        scratchSuccessor(scratchFile, scratchInitLine, scratchInitColumn, scratchLine,
          scratchColumn, successorLine, successorColumn) and
        scratchOption(scratchFile, successorLine, successorColumn, successorKind,
          successorAlignment, successorSize) and
        layoutInSequence(layoutFile, layoutInitLine, layoutInitColumn, layoutSuccessorLine,
          layoutSuccessorColumn, layoutSuccessorKind, layoutSuccessorAlignment, layoutSuccessorSize) and
        positionBefore(layoutLine, layoutColumn, layoutSuccessorLine, layoutSuccessorColumn) and
        optionsMatch(layoutSuccessorKind, layoutSuccessorAlignment, successorKind,
          successorAlignment)
      )
    )
  )
}

private predicate plausiblePair(
  File scratchFile, int scratchInitLine, int scratchInitColumn, File layoutFile, int layoutInitLine,
  int layoutInitColumn
) {
  /* Do not diagnose standalone scratch layout builders or unrelated sequences. */
  relatedSourceFiles(layoutFile, scratchFile) and
  exists(
    int scratchLine, int scratchColumn, string scratchAlignment, string scratchSize, int layoutLine,
    int layoutColumn, string layoutAlignment, string layoutSize
  |
    scratchInSequence(scratchFile, scratchInitLine, scratchInitColumn, scratchLine, scratchColumn,
      "FD_SCRATCH_ALLOC_APPEND", scratchAlignment, scratchSize) and
    layoutInSequence(layoutFile, layoutInitLine, layoutInitColumn, layoutLine, layoutColumn,
      "FD_LAYOUT_APPEND", layoutAlignment, layoutSize) and
    layoutAlignment = scratchAlignment and
    layoutSize = scratchSize
  )
}

private predicate sequenceMatches(
  File scratchFile, int scratchInitLine, int scratchInitColumn, File layoutFile, int layoutInitLine,
  int layoutInitColumn
) {
  plausiblePair(scratchFile, scratchInitLine, scratchInitColumn, layoutFile, layoutInitLine,
    layoutInitColumn) and
  not exists(int line, int column, string kind, string alignment, string size |
    scratchInSequence(scratchFile, scratchInitLine, scratchInitColumn, line, column, kind,
      alignment, size) and
    not orderedOptionMatch(scratchFile, scratchInitLine, scratchInitColumn, layoutFile,
      layoutInitLine, layoutInitColumn, line, column, kind, alignment)
  )
}

from ScratchOption init, File scratchFile, int scratchInitLine, int scratchInitColumn
where
  init.getMacroName() = "FD_SCRATCH_ALLOC_INIT" and
  scratchFile = init.getActualLocation().getFile() and
  scratchInitLine = init.getActualLocation().getEndLine() and
  scratchInitColumn = init.getActualLocation().getEndColumn() and
  exists(File layoutFile, int layoutInitLine, int layoutInitColumn |
    plausiblePair(scratchFile, scratchInitLine, scratchInitColumn, layoutFile, layoutInitLine,
      layoutInitColumn)
  ) and
  not exists(File layoutFile, int layoutInitLine, int layoutInitColumn |
    sequenceMatches(scratchFile, scratchInitLine, scratchInitColumn, layoutFile, layoutInitLine,
      layoutInitColumn)
  )
select init,
  "This FD_SCRATCH_ALLOC_* sequence does not match the corresponding FD_LAYOUT_* sequence."
