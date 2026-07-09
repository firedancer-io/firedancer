#define NULL ((void*)0)

struct foo {
    int a;
    long b;
};
typedef struct foo foo_t;

int global_var;
int global_array[10];

// Test direct comparisons with local variables
void test_direct_comparison_local(void) {
    int x;

    // Direct comparison of address-of with NULL - should alert
    if (&x == NULL) {}       // $ Alert
    if (&x != NULL) {}       // $ Alert
    if (NULL == &x) {}       // $ Alert
    if (0 == &x) {}          // $ Alert
}

// Test direct boolean context with local variables
void test_direct_bool_context(void) {
    int x;

    // Direct use in boolean context - should alert
    if (&x) {}               // $ Alert
    if (!&x) {}              // $ Alert
}

// Test dataflow through assignment - should alert
void test_assigned_and_checked(void) {
    int x;
    int *p;

    p = &x;
    if (p == NULL) {}            // $ Alert
}

// Test dataflow through initialization - should alert
void test_initialized_and_checked(void) {
    int x;
    int *q = &x;
    if (q == NULL) {}            // $ Alert
}

// Test struct fields of local structs
void test_local_struct_fields(void) {
    foo_t f;
    int *pa;
    long *pb;

    // Address of struct field - should alert when directly checked
    if (&f.a == NULL) {}     // $ Alert
    if (&f.b == NULL) {}     // $ Alert

    pa = &f.a;
    if (pa == NULL) {}           // $ Alert

    pb = &f.b;
    if (pb == NULL) {}           // $ Alert
}

// Test array elements of local arrays
void test_local_array_elements(void) {
    int arr[10];
    int *p;

    // Address of array element - should alert when directly checked
    if (&arr[0] == NULL) {}  // $ Alert
    if (&arr[5] == NULL) {}  // $ Alert

    p = &arr[3];
    if (p == NULL) {}            // $ Alert
}

// Test global variables
void test_global_variables(int param_var) {
    int *p;
    int local_var;

    // Tracking issue for the weirdness related to globals:
    // https://github.com/github/codeql/issues/21241
    if (&global_var == NULL) {}      // $ Missing: Alert
    if (&global_var != NULL) {}      // $ Missing: Alert
    if (&global_var) {}              // $ Alert
    if (!&global_var) {}             // $ Missing: Alert

    if (&local_var == NULL) {}       // $ Alert
    if (&local_var != NULL) {}       // $ Alert
    if (&local_var) {}               // $ Alert
    if (!&local_var) {}              // $ Alert

    if (&param_var == NULL) {}       // $ Alert
    if (&param_var != NULL) {}       // $ Alert
    if (&param_var) {}               // $ Alert
    if (!&param_var) {}              // $ Alert
    p = &global_var;
    if (p == NULL) {}                // $ Alert

    if (&global_array[0] == NULL) {} // $ Missing: Alert
}

// Test parameters
void test_parameters(int param, int param_arr[10]) {
    int *p;

    if (&param == NULL) {}        // $ Alert
    p = &param;
    if (p == NULL) {}             // $ Alert

    // Array parameter element
    if (&param_arr[0] == NULL) {} // $ Alert
}

// Test that reassignment breaks the dataflow - should NOT alert
void test_reassignment_breaks_flow(int *other) {
    int x;
    int *p;

    p = &x;                  // NO Alert - p is reassigned before the check
    p = other;               // p is reassigned to something that could be NULL
    if (p == NULL) {}        // This check is valid, p could be NULL here
}

// Test valid pointer checks - should NOT alert
void test_valid_pointer_checks(int *ptr, foo_t *fptr) {
    // These are checking actual pointers, not address-of results
    if (ptr == NULL) {}      // NO Alert - ptr is a parameter that could be NULL
    if (fptr == NULL) {}     // NO Alert - fptr is a parameter that could be NULL
}

// Test pointer arithmetic - should NOT alert
void test_pointer_arithmetic(void) {
    int arr[10];
    int *p = arr + 5;        // NO Alert - this is pointer arithmetic, not address-of
    if (p == NULL) {}        // NO Alert
}

// Test conditional assignment - dataflow should still catch it
void test_conditional_assignment(int cond) {
    int x;
    int *p;

    if (cond) {
        p = &x;
    } else {
        p = &x;
    }
    if (p == NULL) {}            // $ Missing: Alert (every path leads to &x)
}

// Test address-of through pointer dereference
// This case is tricky - &(*ptr) is semantically equivalent to ptr
// but syntactically it's an address-of expression
void test_deref_addrof(int *ptr) {
    // &(*ptr) is equivalent to ptr IFF ptr is not NULL.
    // This should alert IMHO because dereferencing
    // ptr would be invalid if ptr could be NULL
    // CodeQL's extractor (?) fuses &(*ptr) to ptr, so we cannot detect this case currently...
    if (&(*ptr) == NULL) {}  // $ Missing: Alert
}

// Test logical operators as sink
void test_logical_operators(void) {
    int x;
    int *p = &x;

    if (p && *p > 0) {}      // $ Alert
}

// Test ternary operator as sink
void test_ternary(void) {
    int x;
    int *p = &x;

    int result = p ? *p : 0;  // $ Alert
}

struct node
{
    int left;
    int right;
};
// Test address-of of with a recursive function
// nodes is an array of struct node
// left and right are indices into the array
// Function is called like: test_recursive_function(nodes, &nodes[0]);
void test_recursive_function(struct node *nodes, struct node *node)
{
    if (node == NULL)
        return;
    test_recursive_function(nodes, &nodes[node->left]);
}