# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Standalone restricted CPython integer-function worker; no candidate imports or calls."""

from __future__ import annotations

import ast
import json
import sys
from typing import Any

VERSION = "3.12.14"
MAX_SOURCE = 4096
MAX_CASES = 41
ALLOWED = (
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.IfExp,
    ast.Compare,
    ast.BoolOp,
    ast.Name,
    ast.Load,
    ast.Constant,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.FloorDiv,
    ast.Mod,
    ast.USub,
    ast.UAdd,
    ast.Not,
    ast.And,
    ast.Or,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
)


def validate_source(source: str) -> ast.Expression:
    """Accept only transform(x) with one return expression in the fixed finite AST profile."""
    if not isinstance(source, str) or not 1 <= len(source.encode()) <= MAX_SOURCE:
        raise ValueError("source-bound")
    module = ast.parse(source)
    if len(module.body) != 1 or not isinstance(module.body[0], ast.FunctionDef):
        raise ValueError("function")
    function = module.body[0]
    args = function.args
    if (
        function.name != "transform"
        or function.decorator_list
        or function.returns
        or function.type_params
        or args.posonlyargs
        or args.kwonlyargs
        or args.defaults
        or args.kw_defaults
        or args.vararg
        or args.kwarg
        or len(args.args) != 1
        or args.args[0].arg != "x"
        or args.args[0].annotation
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Return)
        or function.body[0].value is None
    ):
        raise ValueError("signature")
    expression = ast.Expression(function.body[0].value)
    nodes = list(ast.walk(expression))
    if len(nodes) > 128:
        raise ValueError("ast-bound")
    for node in nodes:
        if not isinstance(node, ALLOWED):
            raise ValueError("syntax")
        if isinstance(node, ast.Name) and node.id != "x":
            raise ValueError("name")
        if isinstance(node, ast.Constant) and (
            type(node.value) is not int or abs(node.value) > 10000
        ):
            raise ValueError("constant")
    return expression


def execute(source: str, cases: list[int]) -> list[int]:
    """Run the validated expression with no builtins and bounded integer input/output."""
    expression = validate_source(source)
    if not 1 <= len(cases) <= MAX_CASES or any(
        type(item) is not int or abs(item) > 100 for item in cases
    ):
        raise ValueError("cases")
    compiled = compile(expression, "<bounded-function>", "eval")
    values = []
    for item in cases:
        # Only the validated arithmetic AST is executable; names/calls/attributes are excluded.
        value: Any = eval(compiled, {"__builtins__": {}}, {"x": item})  # noqa: S307
        if type(value) is not int or abs(value) > 1_000_000:
            raise ValueError("result")
        values.append(value)
    return values


def main() -> int:
    try:
        if sys.version.split()[0] != VERSION:
            raise ValueError("version")
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise ValueError("input-bound")
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"source", "cases"}:
            raise ValueError("fields")
        result = {"values": execute(value["source"], value["cases"])}
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except (ValueError, TypeError, SyntaxError, ArithmeticError, RecursionError, MemoryError):
        sys.stdout.write('{"status":"error"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
