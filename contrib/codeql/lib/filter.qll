/**
 * Exclude agave code and whatever else we don't want to analyze.
 */
import cpp

private predicate codeqlTestMode() {
  exists(Macro m | m.hasName("__CODEQL_TEST__"))
}

predicate included(Location loc) {
  codeqlTestMode() or loc.getFile().getRelativePath().prefix(4) = "src/"
}
