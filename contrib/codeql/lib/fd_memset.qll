import cpp

/**
 * A `memset`-style function, including `fd_memset`, `bzero` and `__builtin_memset`.
 */
class MemsetFunction extends Function {
  MemsetFunction() {
    this.hasGlobalName("fd_memset")
    or
    this.hasGlobalOrStdOrBslName("memset")
    or
    this.hasGlobalName(["bzero", "__builtin_memset"])
  }

  int sizeIdx() {
    result = 1 and this.hasGlobalName("bzero")
    or
    result = 2 and not this.hasGlobalName("bzero")
  }
}
