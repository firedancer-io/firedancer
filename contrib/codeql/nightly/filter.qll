/**
 * Exclude agave code and whatever else we don't want to analyze.
 */
import cpp
predicate included(Location loc) {
  loc.getFile().getRelativePath().prefix(6) != "agave/"
}
