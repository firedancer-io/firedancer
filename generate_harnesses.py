#!/usr/bin/env python3

import sys
import re

# Function signature templates
FUNCTION_TEMPLATES = {
    # Basic arithmetic operations
    "fd_f25519_mul": {"params": 2, "type": "binary_op"},
    "fd_f25519_sqr": {"params": 1, "type": "unary_op"},
    "fd_f25519_add": {"params": 2, "type": "binary_op"},
    "fd_f25519_sub": {"params": 2, "type": "binary_op"},
    "fd_f25519_add_nr": {"params": 2, "type": "binary_op"},
    "fd_f25519_sub_nr": {"params": 2, "type": "binary_op"},
    "fd_f25519_neg": {"params": 1, "type": "unary_op"},
    "fd_f25519_mul_121666": {"params": 1, "type": "unary_op"},
    "fd_f25519_inv": {"params": 1, "type": "unary_op"},

    # Conversion operations
    "fd_f25519_frombytes": {"params": 1, "type": "from_bytes"},
    "fd_f25519_tobytes": {"params": 1, "type": "to_bytes"},

    # Other operations
    "fd_f25519_set": {"params": 1, "type": "unary_op"},
    "fd_f25519_is_zero": {"params": 1, "type": "predicate"},
    "fd_f25519_pow22523": {"params": 1, "type": "unary_op"},
    "fd_f25519_sqrt_ratio": {"params": 2, "type": "binary_op_return_int"},
}

# Common header template
HEADER_TEMPLATE = """#include <stdio.h>
#include "fd_f25519.h"

int main(int argc FD_PARAM_UNUSED, char** argv FD_PARAM_UNUSED) {{
{main_body}
  return 0;
}}
"""

def generate_harness(function_name, function_info):
    # Generate function declaration
    if function_name == "fd_f25519_tobytes":
        function_decl = "uchar *{}(uchar out[32], fd_f25519_t const *a)".format(function_name)
    elif function_name == "fd_f25519_frombytes":
        function_decl = "fd_f25519_t *{}(fd_f25519_t *r, uchar const buf[32])".format(function_name)
    elif function_name == "fd_f25519_sqrt_ratio":
        function_decl = "int {}(fd_f25519_t *r, fd_f25519_t const *u, fd_f25519_t const *v)".format(function_name)
    elif function_name == "fd_f25519_is_zero":
        function_decl = "int {}(fd_f25519_t const *a)".format(function_name)
    elif function_info["params"] == 1:
        function_decl = "fd_f25519_t *{}(fd_f25519_t *r, fd_f25519_t const *a)".format(function_name)
    else:  # params == 2
        function_decl = "fd_f25519_t *{}(fd_f25519_t *r, fd_f25519_t const *a, fd_f25519_t const *b)".format(function_name)

    # Generate main body based on function type
    main_body = ""

    if function_info["type"] == "unary_op":
        main_body = """  fd_f25519_t a, r;

  // Read input a
  for (int i = 0; i < 5; i++) {{
    if (scanf("%lu", &a.el[i]) != 1) {{
      fprintf(stderr, "Error reading input\\n");
      return 1;
    }}
  }}

  // Perform operation
  {}(&r, &a);

  // Output result
  for (int i = 0; i < 5; i++) {{
    printf("%lu ", r.el[i]);
  }}
  printf("\\nDONE.\\n");""".format(function_name)

    elif function_info["type"] == "binary_op":
        main_body = """  fd_f25519_t a, b, r;

  // Read input a
  for (int i = 0; i < 5; i++) {{
    if (scanf("%lu", &a.el[i]) != 1) {{
      fprintf(stderr, "Error reading input a\\n");
      return 1;
    }}
  }}

  // Read input b
  for (int i = 0; i < 5; i++) {{
    if (scanf("%lu", &b.el[i]) != 1) {{
      fprintf(stderr, "Error reading input b\\n");
      return 1;
    }}
  }}

  // Perform operation
  {}(&r, &a, &b);

  // Output result
  for (int i = 0; i < 5; i++) {{
    printf("%lu ", r.el[i]);
  }}
  printf("\\nDONE.\\n");""".format(function_name)

    elif function_info["type"] == "binary_op_return_int":
        main_body = """  fd_f25519_t u, v, r;
  int result;

  // Read input u
  for (int i = 0; i < 5; i++) {{
    if (scanf("%lu", &u.el[i]) != 1) {{
      fprintf(stderr, "Error reading input u\\n");
      return 1;
    }}
  }}

  // Read input v
  for (int i = 0; i < 5; i++) {{
    if (scanf("%lu", &v.el[i]) != 1) {{
      fprintf(stderr, "Error reading input v\\n");
      return 1;
    }}
  }}

  // Perform operation
  result = {}(&r, &u, &v);

  // Output result
  printf("Return: %d\\n", result);
  for (int i = 0; i < 5; i++) {{
    printf("%lu ", r.el[i]);
  }}
  printf("\\nDONE.\\n");""".format(function_name)

    elif function_info["type"] == "predicate":
        main_body = """  fd_f25519_t a;
  int result;

  // Read input a
  for (int i = 0; i < 5; i++) {{
    if (scanf("%lu", &a.el[i]) != 1) {{
      fprintf(stderr, "Error reading input\\n");
      return 1;
    }}
  }}

  // Perform operation
  result = {}(&a);

  // Output result
  printf("%d\\nDONE.\\n", result);""".format(function_name)

    elif function_info["type"] == "from_bytes":
        main_body = """  fd_f25519_t r;
  uchar buf[32];

  // Read 32 bytes
  for (int i = 0; i < 32; i++) {{
    unsigned int temp;
    if (scanf("%02x", &temp) != 1) {{
      fprintf(stderr, "Error reading input\\n");
      return 1;
    }}
    buf[i] = (uchar)temp;
  }}

  // Convert from bytes
  {}(&r, buf);

  // Output result
  for (int i = 0; i < 5; i++) {{
    printf("%lu ", r.el[i]);
  }}
  printf("\\nDONE.\\n");""".format(function_name)

    elif function_info["type"] == "to_bytes":
        main_body = """  fd_f25519_t a;
  uchar out[32];

  // Read input a
  for (int i = 0; i < 5; i++) {{
    if (scanf("%lu", &a.el[i]) != 1) {{
      fprintf(stderr, "Error reading input\\n");
      return 1;
    }}
  }}

  // Convert to bytes
  {}(out, &a);

  // Output result
  for (int i = 0; i < 32; i++) {{
    printf("%02x", out[i]);
  }}
  printf("\\nDONE.\\n");""".format(function_name)

    # Fill in the header template
    harness_code = HEADER_TEMPLATE.format(function_decl=function_decl, main_body=main_body)
    return harness_code

def generate_all_harnesses():
    for function_name, function_info in FUNCTION_TEMPLATES.items():
        harness_code = generate_harness(function_name, function_info)
        filename = f"src/ballet/ed25519/test_{function_name}.c"
        with open(filename, "w") as f:
            f.write(harness_code)
        print(f"Generated harness for {function_name} in {filename}")
    for function_name, function_info in FUNCTION_TEMPLATES.items():
        print(f"$(call make-unit-test,test_{function_name},test_{function_name},fd_ballet fd_util)")


def print_usage():
    print("Usage:")
    print("  ./generate_harness.py [function_name]")
    print("  If no function name is provided, generates harnesses for all functions")
    print("Available functions:")
    for function_name in sorted(FUNCTION_TEMPLATES.keys()):
        print(f"  {function_name}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] in FUNCTION_TEMPLATES:
            function_name = sys.argv[1]
            harness_code = generate_harness(function_name, FUNCTION_TEMPLATES[function_name])
            filename = f"src/ballet/ed25519/test_{function_name}.c"
            with open(filename, "w") as f:
                f.write(harness_code)
            print(f"Generated harness for {function_name} in {filename}")
        elif sys.argv[1] in ["-h", "--help"]:
            print_usage()
        else:
            print(f"Unknown function: {sys.argv[1]}")
            print_usage()
            sys.exit(1)
    else:
        generate_all_harnesses()