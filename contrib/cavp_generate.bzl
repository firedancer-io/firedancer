"""
Bazel rule to generate C sources given CAVP response files.
"""

def _cc_generate_cavp_test_vector_impl(ctx):
    tool_inputs, tool_input_mfs = ctx.resolve_tools(tools = [ctx.attr._tool])

    output_file = ctx.actions.declare_file(ctx.label.name)

    args = ctx.actions.args()
    args.add("--name", ctx.attr.id)
    args.add("--rsp", ctx.file.response_file)
    args.add("--alg", ctx.attr.algorithm)
    args.add("--out", output_file.path)

    ctx.actions.run(
        outputs = [output_file],
        inputs = [ctx.file.response_file],
        tools = tool_inputs,
        executable = ctx.executable._tool,
        mnemonic = "CavpGenerate",
        arguments = [args],
        input_manifests = tool_input_mfs,
    )

    return [
        DefaultInfo(
            files = depset([output_file]),
            runfiles = ctx.runfiles(files = [output_file]),
        ),
        CcInfo(
            compilation_context = cc_common.create_compilation_context(
                headers = depset([output_file]),
                quote_includes = depset([ctx.genfiles_dir.path + "/" + ctx.label.package]),
            ),
        ),
    ]

cc_generate_cavp_test_vector = rule(
    doc = "Invokes the cavp_generate.py script on CAVP test vectors.\n" +
          "Resulting target should be specified in cc_library deps.\n" +
          "Adds a quote include (header) equal to the target name, rooted in the Bazel package dir.",
    implementation = _cc_generate_cavp_test_vector_impl,
    attrs = {
        "algorithm": attr.string(
            mandatory = True,
            doc = "See --alg flag of cavp_generate.py",
        ),
        "response_file": attr.label(
            allow_single_file = True,
            mandatory = True,
            doc = "See --rsp flag of cavp_generate.py",
        ),
        "id": attr.string(
            mandatory = True,
            doc = "See --name flag of cavp_generate.py",
        ),
        "_tool": attr.label(
            default = "//:contrib/cavp_generate",
            executable = True,
            cfg = "exec",
        ),
    },
    toolchains = ["@bazel_tools//tools/python:toolchain_type"],
    output_to_genfiles = True,
)
