"""Standard-library-only, non-executing inventory of explicit prompt sources."""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys
import tokenize


SOURCE_PATHS = ("agent/prompt_builder.py", "agent/system_prompt.py")


class InventoryError(Exception):
    """A safe diagnostic that never includes prompt source contents."""


def _source_paths(root):
    try:
        root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise InventoryError("invalid root: directory unavailable") from exc
    if not root.is_dir():
        raise InventoryError("invalid root: expected a directory")
    paths = []
    for relative in SOURCE_PATHS:
        candidate = root / relative
        try:
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root):
                raise InventoryError(f"{relative}: escapes root")
            if not resolved.exists():
                raise InventoryError(f"{relative}: missing source file")
            if not resolved.is_file():
                raise InventoryError(f"{relative}: expected a regular file")
        except (OSError, RuntimeError, ValueError) as exc:
            raise InventoryError(f"{relative}: cannot resolve source file") from exc
        paths.append((relative, resolved))
    return paths


def _parse_source(relative, path):
    try:
        with tokenize.open(path) as source:
            return ast.parse(source.read(), filename=relative)
    except SyntaxError as exc:
        # SyntaxError's normal rendering includes the offending source line.
        line = f" at line {exc.lineno}" if exc.lineno is not None else ""
        raise InventoryError(f"{relative}: syntax error{line}") from exc
    except (UnicodeError, LookupError) as exc:
        raise InventoryError(f"{relative}: invalid source encoding") from exc
    except OSError as exc:
        raise InventoryError(f"{relative}: cannot read source file") from exc
    except (ValueError, RecursionError) as exc:
        raise InventoryError(f"{relative}: cannot parse source file") from exc


def _text_constants(tree, relative):
    records = []
    # Only direct module-level assignments, never evaluation or constant folding.
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                records.append({
                    "name": target.id,
                    "path": relative,
                    "line": node.lineno,
                    "character_count": len(value.value),
                    "sha256": hashlib.sha256(value.value.encode("utf-8", errors="surrogatepass")).hexdigest(),
                })
    return records


def inventory(root):
    """Return metadata, not prompt bodies or a runtime-effective prompt.

    Only the two SOURCE_PATHS are read. No agent module, configuration, or
    dynamically referenced source is imported. Symlinks must resolve within root.
    """
    constants = []
    candidates = []
    for relative, path in _source_paths(root):
        tree = _parse_source(relative, path)
        constants.extend(_text_constants(tree, relative))
        if relative == "agent/system_prompt.py":
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "append"):
                    candidates.append({
                        "path": relative,
                        "line": node.lineno,
                        "column": node.col_offset,
                        "call": "append",
                    })
    constants.sort(key=lambda record: (record["path"], record["line"], record["name"]))
    candidates.sort(key=lambda record: (record["path"], record["line"], record["column"]))
    return {
        "kind": "static_prompt_source_inventory",
        "runtime_effective_prompt": False,
        "text_constants": constants,
        "assembly_candidates": candidates,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root (default: current directory)")
    args = parser.parse_args(argv)
    try:
        result = inventory(args.root)
    except InventoryError as exc:
        print(f"prompt_inventory: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
