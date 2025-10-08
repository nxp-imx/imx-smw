# kdoc_extension.py
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 NXP
#
# Generic Sphinx directive that scans C files for various kernel-doc elements
# and emits appropriate ".. kernel-doc::" blocks.
#
# Usage in .rst:
#   .. kdoc-extension:: [file]
#      :structs:                            # Extract all struct declarations
#      :structs: struct_name1 struct_name2  # Document specific structs
#      :functions:                          # Extract all function declarations
#      :functions: func1 func2              # Document specific functions
#      :enums:                              # Extract all enum declarations
#      :enums: enum_name1 enum_name2        # Document specific enums
#      :macros:                             # Extract all macro declarations
#      :macros: MACRO1 MACRO2               # Document specific macros
#      :typedefs:                           # Extract all typedef declarations
#      :typedefs: typedef1 typedef2         # Document specific typedefs
#      :backend: linuxdoc                   # Backend to use (linuxdoc/kerneldoc)

from __future__ import annotations

import os
import re
from typing import List, Set, Dict, Callable

from docutils import nodes, statemachine
from docutils.parsers.rst import directives
from sphinx.util.docutils import SphinxDirective, switch_source_input
from os import path

from fspath import OS_ENV
# Regex patterns for different kernel-doc elements
STRUCT_DECL_RE = re.compile(r"^\s*\*\s*struct\s+([A-Za-z_]\w*)\b\s*-\s*")
FUNCTION_DECL_RE = re.compile(r"^\s*\*\s*([A-Za-z_]\w*)\s*\(\)\s*-\s*")
ENUM_DECL_RE = re.compile(r"^\s*\*\s*enum\s+([A-Za-z_]\w*)\b\s*-\s*")
TYPEDEF_DECL_RE = re.compile(r"^\s*\*\s*typedef\s+([A-Za-z_]\w*)\b\s*-\s*")
# More specific macro patterns
MACRO_UPPER_RE = re.compile(r"^\s*\*\s*([A-Z_][A-Z0-9_]*)\s*-\s*")        # UPPER_CASE
MACRO_LOWER_RE = re.compile(r"^\s*\*\s*([a-z_][a-z0-9_]*)\s*-\s*")        # lower_case
MACRO_CAMEL_RE = re.compile(r"^\s*\*\s*([A-Z][a-zA-Z0-9_]*)\s*-\s*")      # CamelCase
MACRO_FUNC_RE = re.compile(r"^\s*\*\s*([A-Za-z_]\w*)\s*\(\s*[^)]*\s*\)\s*-\s*")  # function_like()

# Open/close of kernel-doc block: "/**" ... "*/"
KDOC_OPEN_RE = re.compile(r"^\s*/\*\*\s*$")
KDOC_CLOSE_RE = re.compile(r"^\s*\*/\s*$")


def resolve_file_path(
    rel_path: str,
    current_source: str = None,
    srctree_override: str = None
) -> tuple[str, str]:
    """
    Resolve a file path that can be relative or absolute.
    Returns (resolved_path, error_message). If error_message is not None, resolution failed.
    """
    if not rel_path:
        return "", "Empty file path provided"

    tmp_name = rel_path

    if rel_path.startswith("/"):
        # Absolute path names are relative to srctree
        tmp_name = rel_path[1:]  # Remove leading slash

        src_tree = (
            srctree_override or
            OS_ENV.get("srctree") or
            os.getcwd()
        )

        if not src_tree:
            return "", "srctree environment variable not set for absolute path"

    else:
        # Relative path - use directory of current source document
        if not current_source:
            return "", "current_source required for relative paths"

        src_tree = path.dirname(path.normpath(current_source))

    try:
        file_path = os.path.abspath(os.path.join(src_tree, tmp_name))
    except (TypeError, ValueError) as e:
        return "", f"Invalid path components: {e}"

    if not os.path.exists(file_path):
        return "", f"File not found: {file_path}"

    return file_path, None

def extract_symbols_by_type(text: str, symbol_type: str) -> List[str]:
    """Extract symbol names of specified type from kernel-doc blocks."""

    pattern_map = {
        'structs': STRUCT_DECL_RE,
        'functions': FUNCTION_DECL_RE,
        'enums': ENUM_DECL_RE,
        'typedefs': TYPEDEF_DECL_RE,
        'macros': [MACRO_UPPER_RE, MACRO_LOWER_RE, MACRO_CAMEL_RE, MACRO_FUNC_RE],  # All macro patterns
    }

    if symbol_type not in pattern_map:
        return []

    patterns = pattern_map[symbol_type]
    if not isinstance(patterns, list):
        patterns = [patterns]

    names: List[str] = []

    if symbol_type == 'macros':
        # Special handling for macros with validation
        names = _extract_documented_macros_with_validation(text, patterns)
    else:
        # Standard extraction for other types
        in_kdoc = False
        for line in text.splitlines():
            if not in_kdoc:
                if KDOC_OPEN_RE.match(line):
                    in_kdoc = True
                continue

            if KDOC_CLOSE_RE.match(line):
                in_kdoc = False
                continue

            for pattern in patterns:
                match = pattern.match(line)
                if match:
                    name = match.group(1)
                    if name not in names:
                        names.append(name)

    return names

def _extract_documented_macros_with_validation(text: str, patterns: List) -> List[str]:
    """
    Extract macros from kernel-doc blocks and validate they have corresponding #define.
    """
    names: List[str] = []
    in_kdoc = False
    current_kdoc_macros = []
    lines = text.splitlines()

    for i, line in enumerate(lines):
        if not in_kdoc:
            if KDOC_OPEN_RE.match(line):
                in_kdoc = True
                current_kdoc_macros = []  # Reset for new kernel-doc block
            continue

        if KDOC_CLOSE_RE.match(line):
            in_kdoc = False
            # Validate that documented macros actually exist in the following code
            _validate_macros_exist(lines, i, current_kdoc_macros, names)
            continue

        # Inside a kernel-doc block - look for macro documentation
        for pattern in patterns:
            match = pattern.match(line)
            if match:
                macro_name = match.group(1)
                if macro_name not in current_kdoc_macros:
                    current_kdoc_macros.append(macro_name)

    return names

def _validate_macros_exist(lines: List[str], kdoc_end_line: int, documented_macros: List[str], names: List[str]):
    """
    Validate that documented macros actually have corresponding #define statements.
    Only look in a small window after the kernel-doc block.
    """
    # Look for #define statements in the next few lines after kernel-doc
    search_window = min(10, len(lines) - kdoc_end_line - 1)

    for i in range(1, search_window + 1):
        if kdoc_end_line + i >= len(lines):
            break

        line = lines[kdoc_end_line + i]

        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith('//') or line.strip().startswith('/*'):
            continue

        # Look for #define statements
        define_match = re.match(r'^\s*#define\s+([A-Za-z_]\w*)', line)
        if define_match:
            defined_macro = define_match.group(1)

            # Only add if this macro was documented in the preceding kernel-doc
            if defined_macro in documented_macros and defined_macro not in names:
                names.append(defined_macro)

        # Stop searching if we hit another kernel-doc or significant code
        elif line.strip().startswith('/**') or line.strip().startswith('struct') or line.strip().startswith('enum'):
            break

class KdocExtensionDirective(SphinxDirective):
    """
    .. kdoc-extension:: path/to/header.h
        :structs:                    # Extract all struct declarations
        :structs: name1 name2        # Extract specific structs
        :functions:                  # Extract all function declarations
        :functions: func1 func2      # Extract specific functions
        :enums:                      # Extract all enum declarations
        :enums: name1 name2          # Extract specific enums
        :macros:                     # Extract all macro declarations
        :macros: MACRO1 MACRO2       # Extract specific macros
        :typedefs:                   # Extract all typedef declarations
        :typedefs: type1 type2       # Extract specific typedefs
        :backend: linuxdoc           # Backend: linuxdoc (default) or kerneldoc

    Scans the specified file for kernel-doc blocks of the requested types and
    emits appropriate `.. kernel-doc::` directives.

    Documentation order: functions, structs, typedefs, macros, enums

    Examples:
        .. kdoc-extension:: include/myheader.h
            :structs:
            :typedefs:
            :macros:

        .. kdoc-extension:: include/myheader.h
            :structs: my_struct another_struct
            :functions: init_device cleanup_device
            :typedefs: my_type_t
            :enums: my_enum
            :macros: MY_MACRO ANOTHER_MACRO

        .. kdoc-extension:: /src/myfile.c
            :functions:
            :typedefs: custom_type_t
            :macros: SPECIFIC_MACRO
            :backend: kerneldoc

        .. kdoc-extension:: include/api.h
            :structs:
            :functions: api_init api_destroy
            :typedefs:
            :enums: error_code status_code
            :macros:
    """

    required_arguments = 1  # the source file
    optional_arguments = 0
    final_argument_whitespace = False

    option_spec = {
        "structs": directives.unchanged,     # Extract structs (flag or space-separated names)
        "functions": directives.unchanged,   # Extract functions (flag or space-separated names)
        "enums": directives.unchanged,       # Extract enums (flag or space-separated names)
        "macros": directives.unchanged,      # Extract macros (flag or space-separated names)
        "typedefs": directives.unchanged,    # Extract typedefs (flag or space-separated names)
        "backend": directives.unchanged,     # "linuxdoc" (default) or "kerneldoc"
    }

    def run(self):
        env = self.env
        rel_path = self.arguments[0]
        rst_doc = getattr(self.state.document, "current_source", None)

        # Resolve file path
        file_path, error_msg = resolve_file_path(rel_path, rst_doc)

        if error_msg:
            msg = self.state_machine.reporter.warning(
                f"[kdoc-extension] {error_msg}"
            )
            return [msg]

        # Read file content
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception as exc:
            msg = self.state_machine.reporter.warning(
                f"[kdoc-extension] Failed to read {file_path}: {exc}"
            )
            return [msg]

        # Define the order in which symbol types should be documented
        # Order: functions, structs, typedefs, macros, enums
        symbol_type_order = ['functions', 'structs', 'typedefs', 'macros', 'enums']

        # Determine which symbol types to extract
        specific_symbols = {
            'structs': [],
            'functions': [],
            'enums': [],
            'macros': [],
            'typedefs': []
        }

        # Track which types were requested
        requested_types = set()

        if "structs" in self.options:
            requested_types.add("structs")
            # Check if specific struct names were provided
            struct_value = self.options.get("structs", "").strip()
            if struct_value:
                specific_symbols['structs'] = struct_value.split()

        if "functions" in self.options:
            requested_types.add("functions")
            # Check if specific function names were provided
            func_value = self.options.get("functions", "").strip()
            if func_value:
                specific_symbols['functions'] = func_value.split()

        if "enums" in self.options:
            requested_types.add("enums")
            # Check if specific enum names were provided
            enum_value = self.options.get("enums", "").strip()
            if enum_value:
                specific_symbols['enums'] = enum_value.split()

        if "macros" in self.options:
            requested_types.add("macros")
            # Check if specific macro names were provided
            macro_value = self.options.get("macros", "").strip()
            if macro_value:
                specific_symbols['macros'] = macro_value.split()

        if "typedefs" in self.options:
            requested_types.add("typedefs")
            # Check if specific typedef names were provided
            typedef_value = self.options.get("typedefs", "").strip()
            if typedef_value:
                specific_symbols['typedefs'] = typedef_value.split()

        if not requested_types:
            msg = self.state_machine.reporter.warning(
                "[kdoc-extension] No symbol types specified. "
                "Use :structs:, :functions:, :enums:, :macros:, or :typedefs:"
            )
            return [msg]

        # Extract symbols for each requested type, following the defined order
        all_symbols: Dict[str, List[str]] = {}
        total_symbols = 0

        # Process in the defined order, but only for requested types
        for symbol_type in symbol_type_order:
            if symbol_type not in requested_types:
                continue

            if specific_symbols[symbol_type]:
                # Use the specific symbol names provided
                symbols = specific_symbols[symbol_type]
            else:
                # Extract all symbols of this type from the file
                symbols = extract_symbols_by_type(text, symbol_type)

            if symbols:
                all_symbols[symbol_type] = symbols
                total_symbols += len(symbols)

        if total_symbols == 0:
            types_str = ", ".join(sorted(requested_types))
            msg = self.state_machine.reporter.info(
                f"[kdoc-extension] No kernel-doc {types_str} declarations "
                f"found in {rel_path}"
            )
            return [msg]

        # Generate kernel-doc directives in the specified order
        return self._generate_kernel_doc_directives(rel_path, all_symbols, file_path, symbol_type_order)

    def _generate_kernel_doc_directives(
        self,
        rel_path: str,
        symbols_by_type: Dict[str, List[str]],
        file_path: str,
        symbol_type_order: List[str]
    ) -> List[nodes.Node]:
        """Generate kernel-doc directive nodes for the extracted symbols in specified order."""

        backend = (self.options.get("backend") or "linuxdoc").strip().lower()

        # Determine the option name based on backend
        backend_options = {
            "kerneldoc": {
                "structs": "identifiers",
                "functions": "functions",
                "enums": "identifiers",
                "macros": "identifiers",
                "typedefs": "identifiers"
            },
            "linuxdoc": {
                "structs": "functions",
                "functions": "functions",
                "enums": "functions",
                "macros": "functions",
                "typedefs": "functions"
            }
        }

        option_map = backend_options.get(backend, backend_options["linuxdoc"])

        result_nodes = []

        # Generate kernel-doc directives in the specified order
        for symbol_type in symbol_type_order:
            if symbol_type not in symbols_by_type:
                continue

            symbols = symbols_by_type[symbol_type]
            if not symbols:
                continue

            opt_name = option_map[symbol_type]

            # Build the directive text
            lines: List[str] = []
            lines.append(f".. kernel-doc:: {rel_path}")

            # Format symbols across multiple lines if needed (wrap at ~100 chars)
            current = f"   :{opt_name}:"
            for symbol in symbols:
                if len(current) + 1 + len(symbol) > 100:
                    lines.append(current)
                    current = " " * 3 + " " * (len(opt_name) + 3) + symbol
                else:
                    current += f" {symbol}"
            lines.append(current)

            # Add a blank line between different symbol types
            lines.append("")

            # Parse the generated directive into nodes
            view = statemachine.ViewList()
            for no, line in enumerate(lines):
                view.append(line, f"{self.__class__.__name__}-gen", no)

            node = nodes.section()
            with switch_source_input(self.state, view):
                self.state.nested_parse(view, 0, node)

            result_nodes.extend(node.children)

        # Tell Sphinx that the page depends on the file we scanned
        self.env.note_dependency(os.path.abspath(file_path))

        return result_nodes
def setup(app):
    app.add_directive("kdoc-extension", KdocExtensionDirective)
    return {
        "version": "1.0",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }