"""Minimal filter expression parser/evaluator."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple


Token = Tuple[str, str]


def _tokenize(expr: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            tokens.append((ch, ch))
            i += 1
            continue
        if expr[i:i+2] in (">=", "<=", "!="):
            tokens.append(("OP", expr[i:i+2]))
            i += 2
            continue
        if ch in "=<>~":
            tokens.append(("OP", ch))
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            start = i
            while i < len(expr) and expr[i] != quote:
                i += 1
            tokens.append(("STRING", expr[start:i]))
            i += 1
            continue
        if ch.isdigit() or (ch == "." and i + 1 < len(expr) and expr[i+1].isdigit()):
            start = i
            i += 1
            while i < len(expr) and (expr[i].isdigit() or expr[i] == "."):
                i += 1
            tokens.append(("NUMBER", expr[start:i]))
            continue
        # identifiers/operators
        start = i
        i += 1
        while i < len(expr) and (expr[i].isalnum() or expr[i] in "_:."):
            i += 1
        ident = expr[start:i]
        low = ident.lower()
        if low in ("and", "or", "not"):
            tokens.append((low.upper(), low))
        else:
            tokens.append(("IDENT", ident))
    tokens.append(("EOF", ""))
    return tokens


def _coerce_value(val: str) -> Any:
    try:
        if "." in val:
            return float(val)
        return int(val)
    except Exception:
        return val
