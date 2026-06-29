import cpp

/**
 * A memcpy function:
 * - `memcpy` from `<string.h>`
 * - `fd_memcpy` from `fd_util_base.h`
 * - `__builtin_memcpy`
 */
class MemcpyFunction extends Function {
  MemcpyFunction() {
    this.hasGlobalOrStdName("memcpy")
    or
    this.hasGlobalName(["fd_memcpy", "__builtin_memcpy"])
  }
}
