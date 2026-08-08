"""Typed argument matchers for policy rules.

A rule argument pattern is either a scalar (the original behaviour: glob
strings, exact values for everything else) or a typed matcher: a JSON object
with an ``operator`` key that names the matcher type. Every typed matcher is
validated when the policy loads; unknown keys, unknown operators, and invalid
field values are all hard policy errors.

Supported matchers and their fields:

``url``
    scheme              str | [str]      equality / membership (lowercased)
    hostname            str | [str]      glob equality / membership
    port                int | [int]      literal port equality / membership
    path                {"equals" | "prefix" | "suffix": str}
    deny_private_networks  bool          only public literal IPs match

    ``deny_private_networks`` classifies the hostname only when it is a
    literal IPv4 or IPv6 address. DNS resolution and HTTP redirects are never
    inspected, and a non-IP hostname is not denied.

``path``
    within              str              lexical absolute containment
    equals              str              lexical absolute equality

``domain``
    equals              str              exact lowercase domain match
    suffix              str              the domain or any of its subdomains

``http_method``
    equals              str              exact method (case-insensitive)
    in                  [str]            membership

``number``
    min                 number           inclusive lower bound
    max                 number           inclusive upper bound

``sql``
    equals              str              leading operation (upper-cased)
    in                  [str]            membership

``command``
    executable          str              glob against argv[0] or its basename
    argv_prefix         [str]            leading argv elements (globs)

    ``argv_prefix`` is matched against the full argv including the executable
    element; when both are given they must both hold. The value may be a
    command string (split lexically with ``shlex``) or an argv list.

Scalar string patterns keep their original glob meaning and everything else
keeps exact equality; only objects with an ``operator`` key opt into a typed
matcher. Matchers never touch the filesystem and never perform DNS lookups.
"""

from __future__ import annotations

import ipaddress
import posixpath
import shlex
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlsplit

OPERATORS = frozenset(
    ("url", "path", "domain", "http_method", "number", "sql", "command")
)

ValidatorFn = Callable[[dict[str, Any], str], None]
MatcherFn = Callable[[dict[str, Any], Any], bool]

URL_FIELDS = frozenset(
    ("operator", "scheme", "hostname", "port", "path", "deny_private_networks")
)
PATH_FIELDS = frozenset(("operator", "within", "equals"))
DOMAIN_FIELDS = frozenset(("operator", "equals", "suffix"))
HTTP_METHOD_FIELDS = frozenset(("operator", "equals", "in"))
NUMBER_FIELDS = frozenset(("operator", "min", "max"))
SQL_FIELDS = frozenset(("operator", "equals", "in"))
COMMAND_FIELDS = frozenset(("operator", "executable", "argv_prefix"))
PATH_OPERATOR_FIELDS = frozenset(("equals", "prefix", "suffix"))


def is_typed(pattern: Any) -> bool:
    return isinstance(pattern, dict) and "operator" in pattern


def compile(pattern: Any, where: str = "matcher") -> None:
    """Validate a typed matcher object, raising ValueError on any problem."""
    if not isinstance(pattern, dict):
        raise ValueError("a typed matcher must be an object")
    operator = pattern.get("operator")
    if operator not in OPERATORS:
        known = ", ".join(sorted(OPERATORS))
        raise ValueError(
            f"unknown matcher operator {operator!r} (expected one of: {known})"
        )
    _VALIDATORS[operator](pattern, where)


def match(pattern: Any, value: Any) -> bool:
    """Match a validated typed matcher against an argument value.

    ``value`` is whatever JSON value the tool call carried. Anything that is
    not the right shape simply does not match.
    """
    if not is_typed(pattern):
        raise ValueError("match() requires a typed matcher object")
    operator = pattern.get("operator")
    if operator not in OPERATORS:
        raise ValueError(f"unknown matcher operator {operator!r}")
    return _MATCHERS[operator](pattern, value)


def _validate(pattern: dict[str, Any], where: str, allowed: frozenset[str]) -> None:
    unknown = [key for key in pattern if key not in allowed]
    if unknown:
        names = ", ".join(f"{where}.{key}" for key in sorted(unknown))
        raise ValueError(f"unknown typed matcher key(s): {names}")


def _require_one_of(
    pattern: dict[str, Any], fields: tuple[str, ...], where: str
) -> None:
    present = [field for field in fields if field in pattern]
    if not present:
        raise ValueError(f"{where} requires one of: {', '.join(fields)}")


def _string_list(value: Any, where: str) -> list[str]:
    if isinstance(value, str) and value:
        return [value]
    if (
        isinstance(value, list)
        and value
        and all(isinstance(item, str) and item for item in value)
    ):
        return list(value)
    raise ValueError(f"{where} must be a non-empty string or list of strings")


def _int_list(value: Any, where: str) -> list[int]:
    if isinstance(value, bool):
        raise ValueError(f"{where} must be an integer or a list of integers")
    if isinstance(value, int):
        if value < 0 or value > 65535:
            raise ValueError(f"{where} must be a port between 0 and 65535")
        return [value]
    if (
        isinstance(value, list)
        and value
        and all(isinstance(item, int) and not isinstance(item, bool) for item in value)
    ):
        if any(item < 0 or item > 65535 for item in value):
            raise ValueError(f"{where} must contain ports between 0 and 65535")
        return list(value)
    raise ValueError(f"{where} must be an integer or a list of integers")


def _non_empty_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where} must be a non-empty string")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{where} must be a boolean")
    return value


def _validate_url(pattern: dict[str, Any], where: str) -> None:
    _validate(pattern, where, URL_FIELDS)
    if "scheme" in pattern:
        _string_list(pattern["scheme"], f"{where}.scheme")
    if "hostname" in pattern:
        _string_list(pattern["hostname"], f"{where}.hostname")
    if "port" in pattern:
        _int_list(pattern["port"], f"{where}.port")
    if "path" in pattern:
        _validate_path_operator(pattern["path"], f"{where}.path")
    if "deny_private_networks" in pattern:
        _bool(pattern["deny_private_networks"], f"{where}.deny_private_networks")
    _require_one_of(
        pattern,
        ("scheme", "hostname", "port", "path", "deny_private_networks"),
        where,
    )


def _validate_path_operator(value: Any, where: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(
            f"{where} must be an object with one of: equals, prefix, suffix"
        )
    _validate(value, where, PATH_OPERATOR_FIELDS)
    present = [key for key in value if key != "operator"]
    if len(present) != 1:
        raise ValueError(f"{where} must have exactly one of: equals, prefix, suffix")
    _non_empty_string(value[present[0]], f"{where}.{present[0]}")


def _validate_path(pattern: dict[str, Any], where: str) -> None:
    _validate(pattern, where, PATH_FIELDS)
    for field in ("within", "equals"):
        if field in pattern:
            _non_empty_string(pattern[field], f"{where}.{field}")
    _require_one_of(pattern, ("within", "equals"), where)


def _validate_domain(pattern: dict[str, Any], where: str) -> None:
    _validate(pattern, where, DOMAIN_FIELDS)
    for field in ("equals", "suffix"):
        if field in pattern:
            _non_empty_string(pattern[field], f"{where}.{field}")
    _require_one_of(pattern, ("equals", "suffix"), where)


def _validate_http_method(pattern: dict[str, Any], where: str) -> None:
    _validate(pattern, where, HTTP_METHOD_FIELDS)
    if "equals" in pattern:
        _non_empty_string(pattern["equals"], f"{where}.equals")
    if "in" in pattern:
        values = _string_list(pattern["in"], f"{where}.in")
        if not values:
            raise ValueError(f"{where}.in must not be empty")
    _require_one_of(pattern, ("equals", "in"), where)
    if "equals" in pattern and "in" in pattern:
        raise ValueError(f"{where}: use either equals or in, not both")


def _validate_number(pattern: dict[str, Any], where: str) -> None:
    _validate(pattern, where, NUMBER_FIELDS)
    for field in ("min", "max"):
        if field in pattern:
            _to_decimal(pattern[field], f"{where}.{field}")
    _require_one_of(pattern, ("min", "max"), where)


def _validate_sql(pattern: dict[str, Any], where: str) -> None:
    _validate(pattern, where, SQL_FIELDS)
    if "equals" in pattern:
        _non_empty_string(pattern["equals"], f"{where}.equals")
    if "in" in pattern:
        values = _string_list(pattern["in"], f"{where}.in")
        if not values:
            raise ValueError(f"{where}.in must not be empty")
    _require_one_of(pattern, ("equals", "in"), where)
    if "equals" in pattern and "in" in pattern:
        raise ValueError(f"{where}: use either equals or in, not both")


def _validate_command(pattern: dict[str, Any], where: str) -> None:
    _validate(pattern, where, COMMAND_FIELDS)
    if "executable" in pattern:
        _non_empty_string(pattern["executable"], f"{where}.executable")
    if "argv_prefix" in pattern:
        values = _string_list(pattern["argv_prefix"], f"{where}.argv_prefix")
        if not values:
            raise ValueError(f"{where}.argv_prefix must not be empty")
    _require_one_of(pattern, ("executable", "argv_prefix"), where)


def _to_decimal(value: Any, where: str) -> Decimal:
    if isinstance(value, bool):
        raise ValueError(f"{where} must be a number")
    if isinstance(value, (int, float)):
        number = Decimal(str(value))
        if not number.is_finite():
            raise ValueError(f"{where} must be a finite number")
        return number
    if isinstance(value, str):
        try:
            number = Decimal(value)
        except InvalidOperation:
            raise ValueError(f"{where} must be a number") from None
        if not number.is_finite():
            raise ValueError(f"{where} must be a finite number")
        return number
    raise ValueError(f"{where} must be a number")


def _match_url(pattern: dict[str, Any], value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    path = parsed.path or ""

    if "scheme" in pattern and not _match_scheme(pattern["scheme"], scheme):
        return False
    if "hostname" in pattern:
        if hostname is None:
            return False
        if not _match_string_list(pattern["hostname"], hostname.lower()):
            return False
    if "port" in pattern:
        if port is None or not _match_int_list(pattern["port"], port):
            return False
    if "path" in pattern:
        if not _match_path_operator(pattern["path"], path):
            return False
    if pattern.get("deny_private_networks") and _is_private_literal(hostname):
        return False
    return True


def _match_string_list(patterns: Any, actual: str) -> bool:
    return any(
        fnmatchcase(actual, item.lower()) for item in _normalized_strings(patterns)
    )


def _match_scheme(patterns: Any, actual: str) -> bool:
    allowed = {item.lower() for item in _normalized_strings(patterns)}
    return actual in allowed


def _match_int_list(patterns: Any, actual: int) -> bool:
    return actual in _normalized_ints(patterns)


def _normalized_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return list(value)
    return [value]


def _normalized_ints(value: Any) -> list[int]:
    if isinstance(value, list):
        return list(value)
    return [value]


def _match_path_operator(pattern: dict[str, Any], actual: str) -> bool:
    for operator in ("equals", "prefix", "suffix"):
        if operator in pattern:
            expected = pattern[operator]
            if operator == "equals":
                return bool(actual == expected)
            if operator == "prefix":
                return actual.startswith(expected)
            return actual.endswith(expected)
    return False


def _is_private_literal(hostname: str | None) -> bool:
    """True when hostname is a literal IP that is not globally routable.

    DNS resolution and redirects are deliberately not inspected: a hostname
    that is not a literal IP is never classified.
    """
    if hostname is None:
        return False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return not address.is_global


def _match_path(pattern: dict[str, Any], value: Any) -> bool:
    if not isinstance(value, str):
        return False
    actual = _lexical_abs(value)
    if "equals" in pattern and actual != _lexical_abs(pattern["equals"]):
        return False
    if "within" in pattern and not _within(_lexical_abs(pattern["within"]), actual):
        return False
    return True


def _lexical_abs(path: str) -> str:
    """Normalize a path to absolute form lexically, with no filesystem access."""
    return posixpath.normpath(posixpath.join("/", path))


def _within(target: str, actual: str) -> bool:
    root = target.rstrip("/")
    return actual == root or actual.startswith(root + "/")


def _match_domain(pattern: dict[str, Any], value: Any) -> bool:
    if not isinstance(value, str) or "@" not in value:
        return False
    domain = value.rsplit("@", 1)[1].lower()
    if "equals" in pattern and domain != pattern["equals"].lower():
        return False
    if "suffix" in pattern:
        suffix = pattern["suffix"].lower()
        if domain != suffix and not domain.endswith("." + suffix):
            return False
    return True


def _match_http_method(pattern: dict[str, Any], value: Any) -> bool:
    if not isinstance(value, str):
        return False
    method = value.strip().upper()
    if "equals" in pattern and method != pattern["equals"].upper():
        return False
    if "in" in pattern:
        allowed = {item.upper() for item in _normalized_strings(pattern["in"])}
        if method not in allowed:
            return False
    return True


def _match_number(pattern: dict[str, Any], value: Any) -> bool:
    number = _value_decimal(value)
    if number is None:
        return False
    if "min" in pattern and number < _to_decimal(pattern["min"], "min"):
        return False
    if "max" in pattern and number > _to_decimal(pattern["max"], "max"):
        return False
    return True


def _value_decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = Decimal(str(value))
        return number if number.is_finite() else None
    if isinstance(value, str):
        try:
            number = Decimal(value)
        except InvalidOperation:
            return None
        return number if number.is_finite() else None
    return None


def _match_sql(pattern: dict[str, Any], value: Any) -> bool:
    if not isinstance(value, str):
        return False
    operation = _sql_operation(value)
    if operation is None:
        return False
    if "equals" in pattern and operation != pattern["equals"].upper():
        return False
    if "in" in pattern:
        allowed = {item.upper() for item in _normalized_strings(pattern["in"])}
        if operation not in allowed:
            return False
    return True


def _sql_operation(statement: str) -> str | None:
    """Return the leading SQL operation, ignoring whitespace and comments."""
    stripped = _strip_sql_comments(statement).strip()
    if not stripped:
        return None
    return stripped.split(maxsplit=1)[0].upper()


def _strip_sql_comments(text: str) -> str:
    output: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in " \t\r\n\f\v":
            output.append(" ")
            index += 1
            continue
        if char == "-" and index + 1 < length and text[index + 1] == "-":
            while index < length and text[index] != "\n":
                index += 1
            continue
        if char == "#":
            while index < length and text[index] != "\n":
                index += 1
            continue
        if char == "/" and index + 1 < length and text[index + 1] == "*":
            index += 2
            while index + 1 < length and not (
                text[index] == "*" and text[index + 1] == "/"
            ):
                index += 1
            index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _match_command(pattern: dict[str, Any], value: Any) -> bool:
    argv = _command_argv(value)
    if not argv:
        return False
    if "executable" in pattern and not _command_executable_matches(
        pattern["executable"], argv[0]
    ):
        return False
    if "argv_prefix" in pattern:
        prefix = _normalized_strings(pattern["argv_prefix"])
        if len(argv) < len(prefix):
            return False
        for actual, expected in zip(argv, prefix):
            if not fnmatchcase(actual, expected):
                return False
    return True


def _command_argv(value: Any) -> list[str] | None:
    if isinstance(value, list):
        if not value or not all(isinstance(item, str) for item in value):
            return None
        return list(value)
    if isinstance(value, str):
        try:
            lexer = shlex.shlex(value, posix=True, punctuation_chars=";&|<>()`")
            lexer.whitespace_split = True
            lexer.commenters = ""
            argv = list(lexer)
        except ValueError:
            return None
        if any(_is_shell_control(token) for token in argv):
            return None
        return argv if argv else None
    return None


def _is_shell_control(token: str) -> bool:
    if token and all(char in ";&|<>()`" for char in token):
        return True
    return "$(" in token or "${" in token


def _command_executable_matches(pattern: str, argv0: str) -> bool:
    if fnmatchcase(argv0, pattern):
        return True
    return fnmatchcase(posixpath.basename(argv0), pattern)


_VALIDATORS: dict[str, ValidatorFn] = {
    "url": _validate_url,
    "path": _validate_path,
    "domain": _validate_domain,
    "http_method": _validate_http_method,
    "number": _validate_number,
    "sql": _validate_sql,
    "command": _validate_command,
}

_MATCHERS: dict[str, MatcherFn] = {
    "url": _match_url,
    "path": _match_path,
    "domain": _match_domain,
    "http_method": _match_http_method,
    "number": _match_number,
    "sql": _match_sql,
    "command": _match_command,
}
