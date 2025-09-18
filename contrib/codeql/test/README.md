# Firedancer CodeQL tests

This directory contains tests for the firedancer specific CodeQL queries.

[CodeQL tests](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/testing-custom-queries) are very simple: they consist of a QL query, and one or more C/C++ files that are used as test cases for the query.
There is a `.expected` file that contains the expected output of the query when run on the test cases.
When the tests are run, the actual output of the query is compared to the expected output, and any differences are reported as test failures.

The tests can either be run in [VS Code](https://docs.github.com/en/code-security/codeql-for-vs-code/using-the-advanced-functionality-of-the-codeql-for-vs-code-extension/testing-codeql-queries-in-vs-code) or via `codeql test run .`

## Contributing to the tests

Ideally, all queries should have tests. Tests should be small and focused, and should illustrate the intended use of the query.

A test should contain both positive and negative cases, i.e. code that should be flagged by the query, and code that should not be flagged by the query.

For example, a test for the "Trivial memcpy" query might contain the following cases:
```c
int array1[10], array2[10];
memcpy(&array1, &array2, sizeof(array2)); // No Alert `array1 = array2;` would be illegal C

foo first;
foo second;
memcpy(&first, &second, sizeof(first)); // $ Alert: trivial memcpy
```

## Query tests

Query tests are located in subdirectories of `query-tests` that are named after the query they are testing.
Each subdirectory contains:
- One or more C/C++ files that contain the test cases.
- A `.ql`/`.qlref` file that contains the query being tested or references an existing query.
- A `.expected` file that contains the expected output of the query when run on the test cases.

For easier query testing, we use [inline expectation tests](https://github.com/github/codeql/pull/17548), which allow us to annotate the test cases with comments that indicate whether a line should produce an alert or not.
For example, the line `memcpy(&first, &second, sizeof(first)); // $ Alert` indicates that this line should produce an alert.

Additionally, we have to use a `.qlref` file that looks like this:
```ql
query: TrivialMemcpy.ql
postprocess: InlineExpectationsTestQuery.ql
```
The crucial step is `postprocess`, which tells CodeQL to run the `InlineExpectationsTestQuery.ql` query after running the `TrivialMemcpy.ql` query.
This postprocessing query compares the results of the `TrivialMemcpy.ql` query to the expectations in the comments and produces the appropriate output.

When there are either missing or unexpected alerts, the test will fail and the `.expected` file will indicate the discrepancies:
```
#select
| expected results...
testFailures
| TrivialMemcpy.c:87:20:87:29 | // $ Alert | Missing result: Alert |
| TrivialMemcpy.c:89:5:89:10 | Call to memcpy could be rewritten as an assignment.foo * | Unexpected result: Alert |
```

When running a test for the first time, it will fail because the `.expected` file is empty/or missing.
To generate the `.expected` file, we can instruct CodeQL to take the actual output of the query as the expected output.
You can do this by right-clicking on the test in the VS Code "Testing" view and selecting "Accept Test Changes" or by running `codeql test run --learn PATH/TO/TEST/DIR`.

## Including files

Standard library headers and third-party library headers cannot be included when building the test database. This is because it would make the test database dependent on the system where it was built, and would also make it dependent on the versions of the libraries installed on that system.

The result is that all external headers have to be mocked.
For example, when using `memcpy` you would write code like this:
```c
typedef unsigned long long size_t;

void *
memcpy(void *restrict dst, const void *restrict src, size_t n);
```

instead of including `<string.h>`.

`#include` directives can still be used to include other files in the same directory as the test file, or in a subdirectory. This is useful for sharing common definitions between multiple test files.