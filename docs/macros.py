"""Macro definitions for documentation."""

# Use built-in 'list' type when upgrading to Python 3.9.

import glob
import os
import re
import textwrap
from io import TextIOWrapper
from typing import List
from urllib.parse import ParseResult, urlparse

from mkdocs_macros.plugin import MacrosPlugin


def define_env(env: MacrosPlugin):
    """
    Define the mkdocs-macros-plugin environment.

    This function is called on setup. 'env' can be interacted with
    for defining variables, macros and filters.

    - variables: the dictionary that contains the environment variables
    - macro: a decorator function, to declare a macro.
    - filter: a function with one or more arguments, used to perform a
    transformation
    """
    # Values can be overridden in mkdocs.yml:extras.
    go_examples_path: str = env.variables.get(
        "go_examples_path", "examples/**/*.go"
    )
    godoc_url: ParseResult = urlparse(
        env.variables.get(
            "godoc_url", "https://pkg.go.dev/github.com/cilium/ebpf"
        )
    )

    c_examples_path: str = env.variables.get("c_examples_path", "examples/**/*.c")

    @env.macro
    def godoc(sym: str, short: bool = False):
        """
        Generate a godoc link based on the configured godoc_url.

        `sym` is the symbol to link to. A dot '.' separator means it's a method
        on another type. Forward slashes '/' can be used to navigate to symbols
        in subpackages.

        For example:
        - CollectionSpec.LoadAndAssign
        - link/Link
        - btf/Spec.TypeByID

        `short` renders only the symbol name.
        """
        if len(godoc_url) == 0:
            raise ValueError("Empty godoc url")

        # Support referring to symbols in subpackages.
        subpkg = os.path.dirname(sym)
        # Symbol name including dots for struct methods. (e.g. Map.Get)
        name = os.path.basename(sym)

        # Python's urljoin() expects the base path to have a trailing slash for
        # it to correctly append subdirs. Use urlparse instead, and interact
        # with the URL's components individually.
        url = godoc_url._replace(
            path=os.path.join(godoc_url.path, subpkg),
            # Anchor token appearing after the # in the URL.
            fragment=name,
        ).geturl()

        text = name
        if short:
            text = text.split(".")[-1]

        return f"[:fontawesome-brands-golang: `{text}`]({url})"

    @env.macro
    def go_example(*args, **kwargs):
        """
        Include the body of a Go code example.

        See docstring of code_example() for details.
        """
        return code_example(
            *args, **kwargs, language="go", path=go_examples_path
        )

    @env.macro
    def c_example(*args, **kwargs):
        """
        Include the body of a C code example.

        See docstring of `code_example` for details.
        """
        return code_example(
            *args, **kwargs, language="c", path=c_examples_path
        )


def code_example(
    symbol: str,
    title: str = None,
    language: str = "",
    lines: bool = True,
    signature: bool = False,
    path: str = "",
) -> str:
    """
    Include the body of a code example.

    `symbol` takes the name of the function or snippet to include.
    `title` is rendered as a title at the top of the snippet.
    `language` is the name of the programming language passed to pygments.
    `lines` controls rendering line numbers.
    `signature` controls whether or not the function signature and brackets are
        included.
    `path` specifies the include path that may contain globs.
    """
    opts: List[str] = []
    if lines:
        opts.append("linenums='1'")
    if title:
        opts.append(f"title='{title}'")

    if signature:
        body = full_body(path, symbol)
    else:
        body = inner_body(path, symbol)

    out = f"``` {language} {' '. join(opts)}\n{body}```"

    return out


def inner_body(path: str, sym: str) -> str:
    """
    Get the inner body of sym, using default delimiters.

    First and last lines (so, function signature and closing bracket) are
    stripped, the remaining body dedented.
    """
    out = _search_body(path, sym)
    if len(out) < 2:
        raise ValueError(
            f"Need at least two lines to get inner body for symbol {sym}"
        )

    return textwrap.dedent("".join(out[1:-1]))


def full_body(path: str, sym: str) -> str:
    """Get the full body of sym, using default delimiters, dedented."""
    out = _search_body(path, sym)

    return textwrap.dedent("".join(out))


def _get_body(
    f: TextIOWrapper, sym: str, start: str = "{", end: str = "}"
) -> List[str]:
    """
    Extract a body of text between sym and start/end delimiters.

    Tailored to finding function bodies of C-family programming languages with
    curly braces.

    The starting line of the body must contain sym prefixed by a space, with
    'start' appearing on the same line, for example " Foo() {". Further
    occurrences of "{" and its closing counterpart "}" are tracked, and the
    lines between and including the final "}" are returned.
    """
    found = False
    stack = 0
    lines = []

    for line in f.readlines():
        if not found:
            # Skip current line if we're not in a body and the current line
            # doesn't contain the given symbol.
            # 
            # The symbol must be surrounded by non-word characters like spaces
            # or parentheses. For example, a line "// DocObjs {" or "func
            # DocLoader() {" should match.
            if re.search(rf"\W{sym}\W", line) is None:
                continue

            found = True

        # Count the amount of start delimiters.
        stack += line.count(start)

        if stack == 0:
            # No opening delimiter found, ignore the line.
            found = False
            continue

        lines.append(line)

        # Count the amount of end delimiters and stop if we've escaped the
        # current scope.
        stack -= line.count(end)
        if stack <= 0:
            break

    # Rewind the file for reuse.
    f.seek(0)

    if stack > 0:
        raise LookupError(f"No end delimiter for {sym}")

    if len(lines) == 0:
        raise LookupError(f"Symbol {sym} not found")

    return lines


def _search_body(path: str, sym: str) -> List[str]:
    """Find the body of the given symbol in a path glob."""
    files = glob.glob(path, recursive=True)
    if len(files) == 0:
        raise LookupError(f"Path {path} did not match any files")

    for file in files:
        with open(file, mode="r") as f:
            try:
                return _get_body(f, sym)
            except LookupError:
                continue

    raise LookupError(f"Symbol {sym} not found in any of {files}")
