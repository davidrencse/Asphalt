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


def _normalize(val: Any) -> Any:
    if isinstance(val, str):
        return val.lower()
    return val


def _field_value(record: Dict[str, Any], field: str) -> Any:
    return record.get(field)


def _compare(op: str, left: Any, right: Any) -> bool:
    if left is None:
        return False
    if isinstance(left, list):
        left_norm = [_normalize(x) for x in left]
    else:
        left_norm = _normalize(left)
    right_norm = _normalize(right)

    if op == "~":
        if isinstance(left_norm, list):
            return any(right_norm in str(x).lower() for x in left_norm)
        return right_norm in str(left_norm).lower()
    if op == "=":
        if isinstance(left_norm, list):
            return right_norm in left_norm
        return left_norm == right_norm
    if op == "!=":
        if isinstance(left_norm, list):
            return right_norm not in left_norm
        return left_norm != right_norm
    try:
        l = float(left_norm)
        r = float(right_norm)
    except Exception:
        return False
    if op == ">":
        return l > r
    if op == ">=":
        return l >= r
    if op == "<":
        return l < r
    if op == "<=":
        return l <= r
    return False


class _Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
