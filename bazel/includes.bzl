"""Tools to prepare C/C++ include dirs"""

load("@bazel_skylib//rules:copy_file.bzl", "copy_file")

def prepare_include_dir(headers, strip_prefix, prefix, **kwargs):
    """Creates a new includes dir.

    Args:
      headers: List of files to be placed in includes dir
      strip_prefix: Prefix to remove from files (e.g. `src`)
      prefix: Prefix to add to files
        (applied after `strip_prefix`, e.g. `include`)
      **kwargs: Passed to Skylib's `copy_file`

    Returns:
      List of files in new includes dir
    """

    targets = []
    for header in headers:
        stem = header.removeprefix(strip_prefix.rstrip("/") + "/")
        target_path = prefix.rstrip("/") + "/" + stem
        rule_name = target_path + "_copy"
        copy_file(
            name = rule_name,
            src = header,
            out = target_path,
            **kwargs
        )
        targets.append(rule_name)
    return targets
