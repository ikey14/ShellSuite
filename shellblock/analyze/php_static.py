"""PHP static stage: one tree-sitter parse, fourteen structural rules.

The file is parsed as a concrete syntax tree with byte offsets, so malformed
webshells still yield usable calls. A single model is cached on the Context and
every detector queries it; nothing is re-parsed per rule.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

import tree_sitter_php
from tree_sitter import Language, Node, Parser

from shellblock.analyze.context import Context
from shellblock.result import Finding, escape_evidence

_LANGUAGE = Language(tree_sitter_php.language_php())
_PARSER = Parser(_LANGUAGE)

_EVAL_SINKS = {"eval", "assert"}
_OS_SINKS = {"system", "exec", "shell_exec", "passthru", "popen", "proc_open"}
_DYNAMIC_SINKS = {"call_user_func", "call_user_func_array"}
_WRITE_SINKS = {"file_put_contents", "move_uploaded_file", "fwrite"}
_DECODERS = {
    "base64_decode",
    "gzinflate",
    "gzuncompress",
    "gzdecode",
    "str_rot13",
    "hex2bin",
    "urldecode",
}
_INCLUDE_TYPES = {
    "include_expression",
    "include_once_expression",
    "require_expression",
    "require_once_expression",
}
_SUPERGLOBALS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"}
_BOOLEAN_FUNCTIONS = {"isset", "empty"}
_EXEC_FAMILIES = {"eval", "os", "dynamic", "custom"}
_DIGEST_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}

_FAMILY = re.compile(
    rb"(c99shell|r57shell|b374k|WSO [0-9]|P\.A\.S\.|@eval\s*\(\s*\$_POST\[)",
    re.IGNORECASE,
)
_BASE64_BLOB = re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}")
_PADDED_TAG = re.compile(rb"[ \t\r\n\f\v\x00]{1024,}(<\?php)")


@dataclass(frozen=True)
class CallSite:
    """A call node with the sink family the walker assigned to it."""

    node: Node
    name: str
    family: str
    arguments: Node | None = None


@dataclass
class PhpModel:
    """Everything the fourteen detectors need, built once per file."""

    root: Node | None
    nodes: list[Node]
    calls: list[CallSite]
    symbols: dict[str, bool]
    http_key_vars: set[str]
    auth_vars: dict[str, dict]
    sink_functions: set[str]


def model(ctx: Context) -> PhpModel:
    """Return the cached model, parsing the buffer on first use."""
    if ctx.php_model is None:
        ctx.php_model = _build(ctx)
    return ctx.php_model


# --------------------------------------------------------------------------
# Model construction
# --------------------------------------------------------------------------
def _build(ctx: Context) -> PhpModel:
    buffer = ctx.buffer
    if b"<?" not in buffer:
        return PhpModel(None, [], [], {}, set(), {}, set())

    root = _PARSER.parse(buffer).root_node
    nodes = list(_walk(root))
    http_keys = _http_key_vars(nodes, buffer)
    symbols = _symbols(nodes, buffer, http_keys)
    sink_functions = _sink_functions(nodes, buffer)
    calls = _calls(nodes, buffer, sink_functions)
    auth_vars = _auth_vars(nodes, buffer, http_keys, symbols)
    return PhpModel(root, nodes, calls, symbols, http_keys, auth_vars, sink_functions)


def _walk(node: Node):
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _text(node: Node, buffer: bytes) -> str:
    return buffer[node.start_byte : node.end_byte].decode("latin-1")


def _var_name(node: Node, buffer: bytes) -> str:
    return _text(node, buffer).lstrip("$")


def _string_value(node: Node | None, buffer: bytes) -> str | None:
    """Literal value of a string node, or None when it interpolates variables."""
    if node is None or node.type not in ("encapsed_string", "string"):
        return None
    for child in node.named_children:
        if child.type not in ("string_content", "escape_sequence"):
            return None
    return "".join(
        _text(child, buffer)
        for child in node.named_children
        if child.type == "string_content"
    )


def _argument(node: Node) -> Node:
    if node.type == "argument" and node.named_children:
        return node.named_children[0]
    return node


def _arguments(node: Node | None) -> list[Node]:
    if node is None:
        return []
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return []
    return [_argument(child) for child in arguments.named_children]


def _call_arguments(call: CallSite) -> list[Node]:
    if call.arguments is None:
        return []
    if call.arguments.type != "arguments":
        return [call.arguments]
    return [_argument(child) for child in call.arguments.named_children]


def _call_name(node: Node, buffer: bytes) -> str:
    function = node.child_by_field_name("function")
    if function is None:
        return ""
    return _text(function, buffer).strip().lstrip("\\").lower()


def _operator(node: Node, buffer: bytes) -> str:
    operator = node.child_by_field_name("operator")
    return _text(operator, buffer) if operator is not None else ""


def _is_variable_function(node: Node) -> bool:
    function = node.child_by_field_name("function")
    return function is not None and function.type == "variable_name"


def _http_key_vars(nodes: list[Node], buffer: bytes) -> set[str]:
    """Variables whose assignment builds an ``HTTP_*`` string."""
    keys: set[str] = set()
    for node in nodes:
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or left.type != "variable_name" or right is None:
            continue
        if _contains_http_literal(right, buffer):
            keys.add(_var_name(left, buffer))
    return keys


def _contains_http_literal(node: Node, buffer: bytes) -> bool:
    for item in _walk(node):
        value = _string_value(item, buffer)
        if value is not None and value.upper().startswith("HTTP_"):
            return True
    return False


def _symbols(nodes: list[Node], buffer: bytes, http_keys: set[str]) -> dict[str, bool]:
    """One-hop table: variable name -> resolves to request input."""
    symbols: dict[str, bool] = {}
    for node in nodes:
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or left.type != "variable_name" or right is None:
            continue
        symbols[_var_name(left, buffer)] = _resolve(right, buffer, symbols, http_keys)
    return symbols


def _resolve(
    node: Node | None,
    buffer: bytes,
    symbols: dict[str, bool],
    http_keys: set[str],
    depth: int = 0,
) -> bool:
    """True when the expression carries request input (default deny)."""
    if node is None or depth > 16:
        return False

    kind = node.type
    if kind == "variable_name":
        if _text(node, buffer) in _SUPERGLOBALS:
            return True
        return symbols.get(_var_name(node, buffer), False)

    if kind == "subscript_expression":
        children = node.named_children
        if not children:
            return False
        base = children[0]
        base_text = _text(base, buffer)
        if base_text in _SUPERGLOBALS:
            return True
        if base_text == "$_SERVER":
            index = children[1] if len(children) > 1 else None
            return _is_http_index(index, buffer, http_keys)
        return _resolve(base, buffer, symbols, http_keys, depth + 1)

    if kind == "function_call_expression":
        name = _call_name(node, buffer)
        if name in _BOOLEAN_FUNCTIONS:
            return False
        if name == "getallheaders":
            return True
        return any(
            _resolve(argument, buffer, symbols, http_keys, depth + 1)
            for argument in _arguments(node)
        )

    if kind in ("encapsed_string", "string"):
        value = _string_value(node, buffer)
        if value is not None:
            return "php://input" in value.lower()
        return any(
            _resolve(child, buffer, symbols, http_keys, depth + 1)
            for child in node.named_children
        )

    if kind == "binary_expression":
        if _operator(node, buffer) != ".":
            return False
        return _resolve(
            node.child_by_field_name("left"), buffer, symbols, http_keys, depth + 1
        ) or _resolve(
            node.child_by_field_name("right"), buffer, symbols, http_keys, depth + 1
        )

    if kind == "conditional_expression":
        return _resolve(
            node.child_by_field_name("body"), buffer, symbols, http_keys, depth + 1
        ) or _resolve(
            node.child_by_field_name("alternative"),
            buffer,
            symbols,
            http_keys,
            depth + 1,
        )

    if kind in (
        "parenthesized_expression",
        "cast_expression",
        "array_creation_expression",
    ):
        return any(
            _resolve(child, buffer, symbols, http_keys, depth + 1)
            for child in node.named_children
        )

    return False


def _is_http_index(
    node: Node | None, buffer: bytes, http_keys: set[str]
) -> bool:
    if node is None:
        return False
    value = _string_value(node, buffer)
    if value is not None:
        return value.upper().startswith("HTTP_")
    if node.type == "variable_name":
        return _var_name(node, buffer) in http_keys
    return False


def _sink_functions(nodes: list[Node], buffer: bytes) -> set[str]:
    """User-defined functions whose body reaches an execution sink."""
    bodies: dict[str, Node] = {}
    for node in nodes:
        if node.type != "function_definition":
            continue
        name = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        if name is not None and body is not None:
            bodies[_text(name, buffer).lower()] = body

    sinks: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, body in bodies.items():
            if name not in sinks and _has_exec_sink(body, buffer, sinks):
                sinks.add(name)
                changed = True
    return sinks


def _has_exec_sink(node: Node, buffer: bytes, custom: set[str]) -> bool:
    for item in _walk(node):
        if item.type == "shell_command_expression":
            return True
        if item.type != "function_call_expression":
            continue
        name = _call_name(item, buffer)
        if (
            name in _EVAL_SINKS
            or name in _OS_SINKS
            or name in _DYNAMIC_SINKS
            or name in custom
        ):
            return True
        if name == "array_map" and _array_map_callback(item, buffer) is not None:
            return True
    return False


def _array_map_callback(node: Node, buffer: bytes) -> str | None:
    arguments = _arguments(node)
    if not arguments:
        return None
    value = _string_value(arguments[0], buffer)
    if value is not None and value.lower() in _EVAL_SINKS:
        return value.lower()
    return None


def _calls(
    nodes: list[Node], buffer: bytes, sink_functions: set[str]
) -> list[CallSite]:
    calls: list[CallSite] = []
    for node in nodes:
        if node.type == "function_call_expression":
            name = _call_name(node, buffer)
            if _is_variable_function(node):
                family = "dynamic"
            elif name in _EVAL_SINKS:
                family = "eval"
            elif name in _OS_SINKS:
                family = "os"
            elif name in _DYNAMIC_SINKS:
                family = "dynamic"
            elif name == "array_map":
                family = "array_map"
            elif name in _WRITE_SINKS:
                family = "write"
            elif name in sink_functions:
                family = "custom"
            else:
                continue
            calls.append(
                CallSite(
                    node,
                    name,
                    family,
                    node.child_by_field_name("arguments"),
                )
            )
        elif node.type == "shell_command_expression":
            arguments = node.named_children[0] if node.named_children else None
            calls.append(CallSite(node, "`...`", "os", arguments))
        elif node.type in _INCLUDE_TYPES:
            arguments = node.named_children[0] if node.named_children else None
            calls.append(CallSite(node, node.type, "include", arguments))
    return calls


def _auth_vars(
    nodes: list[Node],
    buffer: bytes,
    http_keys: set[str],
    symbols: dict[str, bool],
) -> dict[str, dict]:
    auth: dict[str, dict] = {}
    for node in nodes:
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or left.type != "variable_name" or right is None:
            continue
        info = _auth_comparison(right, buffer, http_keys, symbols)
        if info is not None:
            auth[_var_name(left, buffer)] = info
    return auth


def _auth_comparison(
    node: Node,
    buffer: bytes,
    http_keys: set[str],
    symbols: dict[str, bool],
) -> dict | None:
    """Strict credential check: hashed input compared with a digest literal."""
    for item in _walk(node):
        if item.type == "binary_expression" and _operator(item, buffer) in (
            "===",
            "!==",
            "==",
            "!=",
        ):
            left = item.child_by_field_name("left")
            right = item.child_by_field_name("right")
            for hashed, digest in ((left, right), (right, left)):
                info = _hash_info(hashed, buffer, http_keys, symbols)
                if info is None:
                    continue
                value = _string_value(digest, buffer)
                if value is not None and _is_digest(value, info["length"]):
                    return {
                        "algorithm": info["algorithm"],
                        "offset": hashed.start_byte,
                        "end": item.end_byte,
                    }
        if item.type == "function_call_expression" and _call_name(
            item, buffer
        ) in ("strcmp", "strcasecmp", "hash_equals"):
            arguments = _arguments(item)
            for index, argument in enumerate(arguments):
                value = _string_value(argument, buffer)
                if value is None or not _is_digest(value, len(value)):
                    continue
                if len(value) not in _DIGEST_LENGTHS.values():
                    continue
                if any(
                    _resolve(other, buffer, symbols, http_keys)
                    for other_index, other in enumerate(arguments)
                    if other_index != index
                ):
                    return {
                        "algorithm": "digest",
                        "offset": item.start_byte,
                        "end": item.end_byte,
                    }
    return None


def _hash_info(
    node: Node | None,
    buffer: bytes,
    http_keys: set[str],
    symbols: dict[str, bool],
) -> dict | None:
    if node is None or node.type != "function_call_expression":
        return None
    name = _call_name(node, buffer)
    arguments = _arguments(node)
    if name == "hash" and len(arguments) >= 2:
        algorithm = _string_value(arguments[0], buffer)
        if algorithm is None:
            return None
        algorithm = algorithm.lower()
        if algorithm in _DIGEST_LENGTHS and _resolve(
            arguments[1], buffer, symbols, http_keys
        ):
            return {"algorithm": algorithm, "length": _DIGEST_LENGTHS[algorithm]}
    if name in ("md5", "sha1") and arguments:
        if _resolve(arguments[0], buffer, symbols, http_keys):
            return {"algorithm": name, "length": _DIGEST_LENGTHS[name]}
    return None


def _is_digest(value: str, length: int) -> bool:
    return len(value) == length and all(
        character in "0123456789abcdefABCDEF" for character in value
    )


# --------------------------------------------------------------------------
# Findings helpers
# --------------------------------------------------------------------------
def _finding_span(
    rule: dict, ctx: Context, start: int, stop: int, detail: dict
) -> Finding:
    stop = min(stop, len(ctx.buffer))
    return Finding(
        rule_id=rule["id"],
        subject="file",
        severity=rule["severity"],
        location={"kind": "byte_offset", "offset": start},
        evidence=escape_evidence(ctx.buffer[start:stop]),
        detail=detail,
    )


def _node_finding(rule: dict, ctx: Context, node: Node, detail: dict) -> Finding:
    return _finding_span(rule, ctx, node.start_byte, node.end_byte, detail)


def _call_tainted(call: CallSite, ctx: Context) -> bool:
    php = model(ctx)
    if call.family == "dynamic":
        function = call.node.child_by_field_name("function")
        if function is not None and function.type == "variable_name":
            if _resolve(function, ctx.buffer, php.symbols, php.http_key_vars):
                return True
    return any(
        _resolve(argument, ctx.buffer, php.symbols, php.http_key_vars)
        for argument in _call_arguments(call)
    )


def _decoder_depth(node: Node | None, buffer: bytes) -> int:
    if node is None:
        return 0
    best = 0
    if node.type == "function_call_expression" and _call_name(
        node, buffer
    ) in _DECODERS:
        inner = max(
            (_decoder_depth(child, buffer) for child in node.named_children),
            default=0,
        )
        best = 1 + inner
    for child in node.named_children:
        best = max(best, _decoder_depth(child, buffer))
    return best


def _sink_in(node: Node, php: PhpModel, buffer: bytes) -> CallSite | None:
    for call in php.calls:
        if call.family not in _EXEC_FAMILIES and call.family != "array_map":
            continue
        if not (
            call.node.start_byte >= node.start_byte
            and call.node.end_byte <= node.end_byte
        ):
            continue
        if call.family == "array_map" and _array_map_callback(call.node, buffer) is None:
            continue
        return call
    return None


# --------------------------------------------------------------------------
# Detectors (DETECTORS: rule_id -> function)
# --------------------------------------------------------------------------
def find_eval_of_input(ctx: Context, rule: dict) -> list[Finding]:
    """eval/assert reached by request input."""
    return [
        _node_finding(rule, ctx, call.node, {"function": call.name})
        for call in model(ctx).calls
        if call.family == "eval" and _call_tainted(call, ctx)
    ]


def find_os_exec_of_input(ctx: Context, rule: dict) -> list[Finding]:
    """OS command built from request input."""
    return [
        _node_finding(rule, ctx, call.node, {"function": call.name})
        for call in model(ctx).calls
        if call.family == "os" and _call_tainted(call, ctx)
    ]


def find_dynamic_call_of_input(ctx: Context, rule: dict) -> list[Finding]:
    """Dynamic call built from request input or a decoder result."""
    hits: list[Finding] = []
    for call in model(ctx).calls:
        if call.family == "dynamic" and _call_tainted(call, ctx):
            hits.append(_node_finding(rule, ctx, call.node, {"function": call.name}))
        elif call.family == "array_map":
            callback = _array_map_callback(call.node, ctx.buffer)
            if callback is not None and _call_tainted(call, ctx):
                hits.append(
                    _node_finding(rule, ctx, call.node, {"function": callback})
                )
    return hits


def find_include_of_input(ctx: Context, rule: dict) -> list[Finding]:
    """include/require of request input."""
    return [
        _node_finding(rule, ctx, call.node, {"function": call.name})
        for call in model(ctx).calls
        if call.family == "include" and _call_tainted(call, ctx)
    ]


def find_write_of_input(ctx: Context, rule: dict) -> list[Finding]:
    """File write fed by request input."""
    return [
        _node_finding(rule, ctx, call.node, {"function": call.name})
        for call in model(ctx).calls
        if call.family == "write" and _call_tainted(call, ctx)
    ]


def find_exec_sink_only(ctx: Context, rule: dict) -> list[Finding]:
    """Execution sink with no traceable source."""
    hits: list[Finding] = []
    for call in model(ctx).calls:
        if call.family in ("eval", "os", "dynamic") and not _call_tainted(call, ctx):
            hits.append(_node_finding(rule, ctx, call.node, {"function": call.name}))
        elif call.family == "array_map":
            callback = _array_map_callback(call.node, ctx.buffer)
            if callback is not None and not _call_tainted(call, ctx):
                hits.append(
                    _node_finding(rule, ctx, call.node, {"function": callback})
                )
    return hits


def find_obfuscation_ladder(ctx: Context, rule: dict) -> list[Finding]:
    """Two or more decoders nested inside one execution sink."""
    hits: list[Finding] = []
    for call in model(ctx).calls:
        if call.family not in ("eval", "os", "dynamic"):
            continue
        depth = max(
            (_decoder_depth(argument, ctx.buffer) for argument in _call_arguments(call)),
            default=0,
        )
        if depth >= 2:
            hits.append(
                _node_finding(rule, ctx, call.node, {"depth": depth, "function": call.name})
            )
    return hits


def find_known_family(ctx: Context, rule: dict) -> list[Finding]:
    """Known webshell family fingerprint, one finding per family."""
    hits: list[Finding] = []
    seen: set[str] = set()
    for match in _FAMILY.finditer(ctx.buffer):
        family = match.group(0).decode("latin-1").lower()
        if family in seen:
            continue
        seen.add(family)
        hits.append(
            _finding_span(rule, ctx, match.start(), match.end(), {"family": family})
        )
    return hits


def find_auth_gate(ctx: Context, rule: dict) -> list[Finding]:
    """Credential comparison immediately guarding an execution sink."""
    php = model(ctx)
    hits: list[Finding] = []
    for node in php.nodes:
        if node.type != "if_statement":
            continue
        condition = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if condition is None or body is None:
            continue
        info = _auth_comparison(
            condition, ctx.buffer, php.http_key_vars, php.symbols
        )
        if info is None:
            for item in _walk(condition):
                if item.type == "variable_name" and _var_name(
                    item, ctx.buffer
                ) in php.auth_vars:
                    info = php.auth_vars[_var_name(item, ctx.buffer)]
                    break
        if info is None:
            continue
        sink = _sink_in(body, php, ctx.buffer)
        if sink is None:
            continue
        hits.append(
            _finding_span(
                rule,
                ctx,
                info["offset"],
                info.get("end", info["offset"] + 1),
                {"sink": sink.name, "algorithm": info["algorithm"]},
            )
        )
    return hits


def find_request_header_source(ctx: Context, rule: dict) -> list[Finding]:
    """getallheaders() or a $_SERVER['HTTP_*'] read."""
    php = model(ctx)
    hits: list[Finding] = []
    for node in php.nodes:
        if node.type == "function_call_expression" and _call_name(
            node, ctx.buffer
        ) == "getallheaders":
            hits.append(
                _finding_span(
                    rule,
                    ctx,
                    node.start_byte,
                    node.end_byte,
                    {"source": "getallheaders"},
                )
            )
        elif node.type == "subscript_expression" and node.named_children:
            base = node.named_children[0]
            if _text(base, ctx.buffer) != "$_SERVER":
                continue
            index = node.named_children[1] if len(node.named_children) > 1 else None
            if _is_http_index(index, ctx.buffer, php.http_key_vars):
                hits.append(
                    _finding_span(
                        rule,
                        ctx,
                        node.start_byte,
                        node.end_byte,
                        {"source": "$_SERVER[HTTP_*]"},
                    )
                )
    return hits


def find_base64_blob(ctx: Context, rule: dict) -> list[Finding]:
    """A base64 literal of at least 120 characters."""
    return [
        _finding_span(
            rule,
            ctx,
            match.start(),
            match.end(),
            {"length": match.end() - match.start()},
        )
        for match in _BASE64_BLOB.finditer(ctx.buffer)
    ]


def find_high_entropy(ctx: Context, rule: dict) -> list[Finding]:
    """Shannon entropy above 5.5 in a 256-byte window."""
    data = ctx.buffer
    if len(data) < 256:
        return []

    best_entropy = 0.0
    best_offset = 0
    for start in range(0, len(data) - 255, 256):
        window = data[start : start + 256]
        counts = [0] * 256
        for byte in window:
            counts[byte] += 1
        entropy = 0.0
        for count in counts:
            if count:
                probability = count / 256
                entropy -= probability * math.log2(probability)
        if entropy > best_entropy:
            best_entropy = entropy
            best_offset = start

    if best_entropy <= 5.5:
        return []
    return [
        _finding_span(
            rule,
            ctx,
            best_offset,
            best_offset + 256,
            {"entropy": round(best_entropy, 2), "window": 256},
        )
    ]


def find_one_liner(ctx: Context, rule: dict) -> list[Finding]:
    """Three lines or fewer that still reach an execution sink."""
    lines = len(ctx.buffer.splitlines())
    if lines > 3:
        return []
    for call in model(ctx).calls:
        if call.family in _EXEC_FAMILIES:
            return [
                _node_finding(
                    rule, ctx, call.node, {"lines": lines, "function": call.name}
                )
            ]
        if call.family == "array_map":
            callback = _array_map_callback(call.node, ctx.buffer)
            if callback is not None:
                return [
                    _node_finding(
                        rule, ctx, call.node, {"lines": lines, "function": callback}
                    )
                ]
    return []


def find_padded_tag(ctx: Context, rule: dict) -> list[Finding]:
    """<?php hidden after at least 1 KB of whitespace or NULs."""
    return [
        _finding_span(
            rule,
            ctx,
            match.start(1),
            match.end(1),
            {"padding": match.start(1) - match.start()},
        )
        for match in _PADDED_TAG.finditer(ctx.buffer)
    ]
