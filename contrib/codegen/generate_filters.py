#!/usr/bin/env python3

# THE OUTPUT OF THIS SCRIPT HAS TO BE AUDITED.
# We have the choice to spend a lot of energy verifying this compiler or spend
#  a little bit of energy each time verifying its outputs. Given that the code
#  that it generates is succinct and commented, we picked the latter.

# This file contains a naive compiler that turns symbolic expressions into cBPF code.
# Instead of targeting cBPF, the compiler targets C header files.
# This has the advantage of allowing the use of C constants, as long as they are in scope.

import os
import sys
import edn_format
from collections import defaultdict

# Globals holding relocation information.
relo_label_counter = 0
relo_abs_mapping = {}

# new_relo_label provides a unique label on every call
def new_relo_label():
    global relo_label_counter
    relo_label_counter += 1
    return "lbl_%d" % relo_label_counter

# reverse_multi_mapping is useful to turn the map of labels_name -> line to line -> [label_name, ...]
def reverse_multi_mapping(mapping):
    res = defaultdict(list)
    for lbl, idx in mapping.items():
        res[idx].append(lbl)
    return res


# ReloCondJump contains a conditional jump instruction that is not yet realized.
class ReloCondJump(object):
    def __init__(self, code, t_label, f_label, pre_comment=None, post_comment=None):
        self.code = code
        self.t_label = t_label
        self.f_label = f_label
        self.pre_comment = pre_comment
        self.post_comment = post_comment

    def __str__(self):
        return "BPF_JUMP( %s, %s, %s )" % (self.code, self.t_label, self.f_label)

    def relocate(self, instr_idx):
        self.t_label = replace_label(self.t_label, instr_idx=instr_idx)
        self.f_label = replace_label(self.f_label, instr_idx=instr_idx)

# replace_labels replaces an instruction's jump target to the relative distance
def replace_label(label, instr_idx):
    maybe_relo = relo_abs_mapping.get(label)
    if maybe_relo is not None:
        return f"/* {label} */ {maybe_relo - instr_idx - 1}"

    return label

# ReloCondJump contains an unconditional jump instruction that is not yet realized.
class ReloJump(object):
    def __init__(self, label, pre_comment=None, post_comment=None):
        self.label = label
        self.pre_comment = pre_comment
        self.post_comment = post_comment

    def __str__(self):
        return "{ BPF_JMP | BPF_JA, 0, 0, %s }" % (self.label)

    def relocate(self, instr_idx):
        self.label = replace_label(self.label, instr_idx=instr_idx)

# CommentedLiteral is an instruction that has a comment attached.
class CommentedLiteral(object):
    def __init__(self, lit, pre_comment=None, post_comment=None):
        self.lit = lit
        self.pre_comment = pre_comment
        self.post_comment = post_comment

    def __str__(self):
        return self.lit


# append_prelude appends a prelude to the cBPF filter.
def append_prelude(filter):
    filter.append(CommentedLiteral("BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, arch ) ) )", pre_comment="Check: Jump to RET_KILL_PROCESS if the script's arch != the runtime arch"))
    # filter.append("BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 1, 0 )")
    filter.append(ReloCondJump("BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR", 0, "RET_KILL_PROCESS"))
    filter.append(CommentedLiteral("BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, nr ) ) )", pre_comment="loading syscall number in accumulator"))


# codegen generates by appending to filt the bpf code for the policy_lines.
def codegen(policy_lines, filt):
    append_prelude(filt)

    # track all of the expressions that will be appended after the syscall jump table
    syscall_to_expression = {}

    for line_number, line in enumerate(policy_lines):
        lineparts = line.split(':', maxsplit=1)
        lineparts[-1] = lineparts[-1].strip()

        if len(lineparts) == 1:
            syscall = lineparts[0]
            filt.append(ReloCondJump("BPF_JMP | BPF_JEQ | BPF_K, %s" % ('SYS_'+syscall), 'RET_ALLOW', 0, pre_comment="simply allow %s" % syscall))
        elif len(lineparts) == 2:
            syscall = lineparts[0]
            filt.append(ReloCondJump("BPF_JMP | BPF_JEQ | BPF_K, %s" % ('SYS_'+syscall), f'check_{syscall}', 0, pre_comment=f"allow {syscall} based on expression"))
            syscall_to_expression[lineparts[0]] = lineparts[1]
        else:
            print("malformed line @ %s" % (line_number+1), file=sys.stderr)
            sys.exit(1)

    # append the last jump to the syscall jump table
    filt.append(ReloJump("RET_KILL_PROCESS", pre_comment="none of the syscalls matched"))
    # write all of the expression checks

    for syscall, expr in syscall_to_expression.items():
        expression(syscall, expr, filt)

    # register the RET_KILL_PROCESS label
    # it's registered before RET_ALLOW because it's the first fallthrough case for checks
    relo_abs_mapping['RET_KILL_PROCESS'] = len(filt)
    filt.append(CommentedLiteral('BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS )', pre_comment="KILL_PROCESS is placed before ALLOW since it's the fallthrough case."))

    # register the RET_ALLOW label
    relo_abs_mapping['RET_ALLOW'] = len(filt)
    filt.append(CommentedLiteral('BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_ALLOW )', pre_comment="ALLOW has to be reached by jumping"))

    for instr_idx, entry in enumerate(filt):
        if type(entry) is ReloCondJump or type(entry) is ReloJump:
            entry.relocate(instr_idx)

# expression handles a rule with a symbolic expression attached
def expression(name, expr, filt):
    # The check for `name` starts at the next instruction
    relo_abs_mapping[f"check_{name}"] = len(filt)

    expr = edn_format.loads(expr)

    if type(expr) is tuple:
        # Allow the call
        success = 'RET_ALLOW'

        # Write the eval code
        eval_(expr, filt, success, 'RET_KILL_PROCESS')

    elif type(expr) == edn_format.Symbol:
        # Treat the symbol as the desired effect
        filt.append(ReloCondJump("BPF_JMP | BPF_JEQ | BPF_K, %s" % ('SYS_'+name), str(expr), 0))


# eval_ walks through the expression tree and lays instructions down
def eval_(expr, filt, label_t, label_f):
    if type(expr) is tuple:
        expr0_str = str(expr[0])
        if expr0_str == 'not':
            if len(expr) != 2:
                print(expr)
                raise("expecting 1 argument to not")
            # Flip jump labels
            eval_(expr[1], filt, label_f, label_t)

        elif expr0_str == 'and':
            # Assert that there is at least one argument otherwise this is undefined behavior.
            if len(expr) < 2:
                raise("not enough arguments to and")

            for idx, arg in enumerate(expr[1:]):
                if idx == len(expr[1:])-1:
                    # This is the last and entry
                    eval_(arg, filt, label_t, label_f)
                    # Register the end of this eval
                else:
                    next = new_relo_label()
                    eval_(arg, filt, next, label_f)
                    # Register the end of this eval
                    relo_abs_mapping[next] = len(filt)


        elif expr0_str == 'or':
            # Assert that there is at least one argument otherwise this is undefined behavior.
            if len(expr) < 2:
                raise("not enough arguments to or")
            # Evaluate each operand and jump to the negative case if any is false. Ultimately jump to true.

            for idx, arg in enumerate(expr[1:]):
                if idx == len(expr[1:])-1:
                    # This is the last and entry
                    eval_(arg, filt, label_t, label_f)
                else:
                    next = new_relo_label()
                    eval_(arg, filt, label_t, next)
                    relo_abs_mapping[next] = len(filt)

        elif expr0_str == 'arg':
            # Load arg n in accu
            argno = expr[1]
            if type(argno) is not int:
                raise("arg 0 of arg should be int")

            if 0 > argno or argno > 5:
                raise("argno should be between 0 and 5")

            filt.append(CommentedLiteral("BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[%s]))" % argno, pre_comment="load syscall argument %s in accumulator" % argno))

        elif expr0_str == 'bit-and':
            eval_bit_and(filt, expr[1], expr[2], label_t, label_f)

        elif expr0_str == 'eq':
            eval_equal(filt, expr[1], expr[2], label_t, label_f)
        else:
            print(expr0_str)
            raise("unknown fn")

def eval_bit_and(filt, op1, op2, label_t, label_f):
    op1_type, op2_type = type(op1), type(op2)

    if op1_type is not tuple and op2_type is not tuple:
        # handle the case where both values are immediate
        raise("unsupported")

    elif op1_type is tuple and op2_type is not tuple:
        # eval op1 and do operation with op2 imm
        eval_(op1, filt, 0, 0)
        # accu now contains the eval res of op1
        filt.append("{ BPF_ALU | BPF_AND | BPF_K, 0, 0, %s }" % str(op2))

    elif op2_type is tuple and op1_type is not tuple:
        # eval op2 and do operation with op1 imm
        eval_(op2, 0, 0)
        # accu now contains the eval res of op2
        filt.append("{ BPF_ALU | BPF_AND | BPF_K, 0, 0, %s }" % str(op1))
    else:
    # Note: In the case where both are expressions: the res of the first eval must be sent to scratch
        raise("unsupported")

    # if labels were pushed down, it's expected that an action will be taken on the truthiness of the value
    # otherwise, accu will still contain the computed result.
    if label_t and label_f:
        filt.append(ReloCondJump("BPF_JMP | BPF_JEQ | BPF_K, 0", label_f, label_t))

def eval_equal(filt, op1, op2, label_t, label_f):
    op1_type, op2_type = type(op1), type(op2)

    if op1_type is edn_format.Symbol and op2_type is edn_format.Symbol:
        # handle the case where both values are immediate
        # tl;dr: load op1 in accu then cond jump
        # This is not supported because the compiler does not optimize constants.
        # Comparing two immediate values will always yield the same result.
        raise("unsupported")

    elif op1_type is tuple and op2_type is not tuple:
        # eval op1 and do operation with op2 imm
        eval_(op1, filt, None, None)
        # accu now contains the eval res of op1
        filt.append(ReloCondJump("BPF_JMP | BPF_JEQ | BPF_K, %s" % str(op2), label_t, label_f))

    elif op2_type is tuple and op1_type is not tuple:
        # eval op2 and do operation with op1 imm
        eval_(op2, None, None)
        # accu now contains the eval res of op2
        filt.append(ReloCondJump("BPF_JMP | BPF_JEQ | BPF_K, %s" % str(op1), label_t, label_f))
    else:
        # This is unsupported because I didn't pick a calling convention and this means that accu and x should be saved to scratch.
        # It's very easy to achieve but there's no need for it yet. It's basically register allocation over BPF scratch.
        raise("unsupported")


def resplit_lines(lines):
    i = 0
    while i < len(lines):
        if lines[i].startswith(" "):
            lines[i-1] += lines[i]
            lines.pop(i)
        else:
            i += 1
    return lines


if __name__ == '__main__':
    src_path = sys.argv[1]
    filter_name = os.path.basename(src_path)
    if filter_name.endswith(".seccomppolicy"):
        filter_name = filter_name[:-14]
    dst_path_base = filter_name + "_seccomp.h"
    dst_path = os.path.join(
        os.path.dirname(src_path),
        "generated",
        dst_path_base,
    )
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

    with open(src_path) as f:
        with open(dst_path, "w") as of:
            # set child_path to dst_path with the prefix of the parent of this files
            # directory removed.
            child_path = dst_path
            parent_path = os.path.dirname(os.path.realpath(__file__))
            if child_path.startswith("./"):
                child_path = child_path[2:]
            else:
                raise Exception(f"child_path {child_path} does not start with ./")

            num_slashes = child_path.count('/')

            child_path = child_path.replace('/', '_')
            child_path = child_path.replace('.', '_')

            # create a path like "../../" for n num_slashes
            util_path = os.path.join(*([".."] * num_slashes))

            of.write( f"""/* THIS FILE WAS GENERATED BY generate_filters.py. DO NOT EDIT BY HAND! */
#ifndef HEADER_fd_{child_path}
#define HEADER_fd_{child_path}

#include "{util_path}/src/util/fd_util_base.h"
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stddef.h>

#if defined(__i386__)
# define ARCH_NR  AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR  AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define ARCH_NR AUDIT_ARCH_AARCH64
#else
# error "Target architecture is unsupported by seccomp."
#endif
""");

            filter_body = []
            policy_lines = list(filter(lambda line: not line.startswith("#"), f.readlines()))
            policy_lines = resplit_lines(policy_lines)
            policy_lines = list(filter(lambda x: x.strip() != "", policy_lines))
            sigline = policy_lines[0].strip()
            codegen(policy_lines[1:], filter_body)

            line_to_labels = reverse_multi_mapping(relo_abs_mapping)

            of.write("static const unsigned int sock_filter_policy_%s_instr_cnt = %s;\n\n" % (filter_name, len(filter_body)))

            constructor_sig = ""
            if sigline == "noarg":
                constructor_sig = "static void populate_sock_filter_policy_%s( ulong out_cnt, struct sock_filter * out ) {\n" % (filter_name)
            else:
                constructor_sig = "static void populate_sock_filter_policy_%s( ulong out_cnt, struct sock_filter * out, %s) {\n" % (filter_name, sigline)

            of.write(constructor_sig)
            of.write(f"  FD_TEST( out_cnt >= {len(filter_body)} );\n")
            of.write(f"  struct sock_filter filter[{len(filter_body)}] = {{\n");

            padding = "    "
            for lineno, line in enumerate(filter_body):

                maybe_labels = line_to_labels.get(lineno, [])

                for label in maybe_labels:
                    of.write(f"//  {label}:\n")

                if hasattr(line, 'pre_comment'):
                    comment = line.pre_comment
                    if comment != None:
                        of.write(f"{padding}/* {comment} */\n")
                of.write(padding + str(line))
                of.write(',\n')
                if hasattr(line, 'post_comment'):
                    comment = line.post_comment
                    if comment != None:
                        of.write(f"{padding}/* {comment} */\n\n")
            of.write("  };\n")
            of.write("  fd_memcpy( out, filter, sizeof( filter ) );\n")
            of.write("}\n\n")
            of.write("#endif\n")
