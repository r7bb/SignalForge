"""Sigma field-modifier semantics.

One compiled ``FieldMatcher`` per ``field|modifier`` entry in a search.  The
same objects are reused by the in-memory evaluator (streaming detection) and
by the OpenSearch backend (retro-hunting), which is why the semantics live here
rather than in either backend.

Supported modifiers: ``contains``, ``startswith``, ``endswith``, ``all``,
``re`` (with ``i``/``m``/``s`` flags), ``cased``, ``cidr``, ``lt``/``lte``/
``gt``/``gte``, ``exists``, ``base64``, ``base64offset``, ``windash``,
``fieldref`` and ``expand``.
"""

from __future__ import annotations

import base64
import codecs
import ipaddress
import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .errors import SigmaParseError

KNOWN_MODIFIERS = {
    "contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cased",
    "cidr", "lt", "lte", "gt", "gte", "exists", "base64", "base64offset",
    "windash", "fieldref", "expand", "utf16", "utf16le", "utf16be", "wide",
}

_COMPARISON = {"lt", "lte", "gt", "gte"}
_WILDCARD_RE = re.compile(r"(?<!\\)[*?]")


def _to_list(value: Any) -> List[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def glob_to_regex(pattern: str, *, case_sensitive: bool = False) -> "re.Pattern[str]":
    """Translate a Sigma wildcard pattern into an anchored regex.

    ``*`` matches any run of characters, ``?`` exactly one; ``\\*`` and ``\\?``
    are literals.  Everything else is escaped.
    """
    out: List[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern) and pattern[index + 1] in "*?\\":
            out.append(re.escape(pattern[index + 1]))
            index += 2
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        index += 1
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile("^" + "".join(out) + "$", flags | re.DOTALL)


#: Slice bounds used by Sigma's ``base64offset``: the encoding of a value that
#: starts at byte offset 1/2 inside a larger blob keeps only the characters that
#: are independent of the surrounding bytes.
_B64_START = (None, 2, 3)
_B64_END = (None, -3, -2)


def _utf16_encode(text: str, modifiers: Sequence[str]) -> bytes:
    if "utf16be" in modifiers:
        return text.encode("utf-16-be")
    if "utf16le" in modifiers or "wide" in modifiers:
        return text.encode("utf-16-le")
    if "utf16" in modifiers:
        return codecs.BOM_UTF16_LE + text.encode("utf-16-le")
    return text.encode("utf-8")


def _base64_variants(text: str, modifiers: Sequence[str] = ()) -> List[str]:
    """The three byte-offset encodings Sigma's ``base64offset`` looks for."""
    raw = _utf16_encode(text, modifiers)
    variants = []
    for offset in range(3):
        encoded = base64.b64encode(b" " * offset + raw).decode("ascii")
        # The trailing characters are only unambiguous when the padded length
        # is a multiple of 3; otherwise drop the bits the next byte would supply.
        variants.append(encoded[_B64_START[offset]:_B64_END[(len(raw) + offset) % 3]])
    return variants


def _windash_variants(text: str) -> List[str]:
    dashes = ["-", "/", "–", "—", "―"]
    variants = {text}
    if text and text[0] in dashes:
        for dash in dashes:
            variants.add(dash + text[1:])
    return sorted(variants)


@dataclass
class FieldMatcher:
    """A single ``field|modifiers: value(s)`` predicate."""

    field: str
    modifiers: Tuple[str, ...]
    values: Tuple[Any, ...]
    raw_key: str = ""
    _regexes: List[Any] = dc_field(default_factory=list, repr=False)
    _networks: List[Any] = dc_field(default_factory=list, repr=False)

    # -- construction -----------------------------------------------------
    @classmethod
    def compile(cls, key: str, value: Any) -> "FieldMatcher":
        parts = key.split("|")
        field_name = parts[0].strip()
        modifiers = tuple(m.strip().lower() for m in parts[1:] if m.strip())
        unknown = [m for m in modifiers if m not in KNOWN_MODIFIERS]
        if unknown:
            raise SigmaParseError(
                "unsupported field modifier(s) %s in %r" % (", ".join(unknown), key)
            )
        if not field_name:
            raise SigmaParseError("field name missing in %r" % key)
        values = tuple(_to_list(value))
        matcher = cls(field=field_name, modifiers=modifiers, values=values, raw_key=key)
        matcher._prepare()
        return matcher

    def _prepare(self) -> None:
        if "re" in self.modifiers:
            flags = 0
            if "i" in self.modifiers:
                flags |= re.IGNORECASE
            if "m" in self.modifiers:
                flags |= re.MULTILINE
            if "s" in self.modifiers:
                flags |= re.DOTALL
            self._regexes = [re.compile(str(v), flags) for v in self.values]
        elif "cidr" in self.modifiers:
            self._networks = [ipaddress.ip_network(str(v), strict=False) for v in self.values]

    # -- introspection ----------------------------------------------------
    @property
    def is_all(self) -> bool:
        return "all" in self.modifiers

    @property
    def case_sensitive(self) -> bool:
        return "cased" in self.modifiers

    def expanded_values(self) -> List[Any]:
        """Values after string-expansion modifiers (base64/windash)."""
        values: List[Any] = []
        for value in self.values:
            if value is None:
                values.append(None)
                continue
            text = str(value)
            if "base64offset" in self.modifiers:
                values.extend(_base64_variants(text, self.modifiers))
            elif "base64" in self.modifiers:
                values.append(
                    base64.b64encode(_utf16_encode(text, self.modifiers)).decode("ascii")
                )
            elif "windash" in self.modifiers:
                values.extend(_windash_variants(text))
            else:
                values.append(value)
        return values

    # -- evaluation -------------------------------------------------------
    def match(self, flat: Dict[str, Any]) -> bool:
        if "exists" in self.modifiers:
            wants = str(self.values[0]).lower() in {"true", "yes", "1"}
            present = self._present(flat)
            return present == wants

        if "fieldref" in self.modifiers:
            observed = _observed_values(flat, self.field)
            for value in self.values:
                other = _observed_values(flat, str(value))
                if any(self._eq(a, b) for a in observed for b in other):
                    return not self.is_all
            return self.is_all and bool(self.values) and all(
                any(self._eq(a, b) for a in observed for b in _observed_values(flat, str(v)))
                for v in self.values
            )

        observed = _observed_values(flat, self.field)

        # A YAML null means "field absent or explicitly null".
        if any(v is None for v in self.values):
            null_hit = not observed or any(o is None for o in observed)
            others = [v for v in self.values if v is not None]
            if not others:
                return null_hit
            if null_hit and not self.is_all:
                return True

        if not observed:
            return False

        if "re" in self.modifiers:
            results = [
                any(rx.search(str(o)) for o in observed if o is not None) for rx in self._regexes
            ]
            return all(results) if self.is_all else any(results)

        if "cidr" in self.modifiers:
            results = [self._cidr_match(observed, net) for net in self._networks]
            return all(results) if self.is_all else any(results)

        comparison = next((m for m in self.modifiers if m in _COMPARISON), None)
        if comparison:
            results = [self._compare(observed, comparison, v) for v in self.values]
            return all(results) if self.is_all else any(results)

        results = [self._value_match(observed, v) for v in self.expanded_values() if v is not None]
        if not results:
            return False
        return all(results) if self.is_all else any(results)

    def _present(self, flat: Dict[str, Any]) -> bool:
        values = _observed_values(flat, self.field)
        return bool(values) and any(v is not None for v in values)

    def _value_match(self, observed: Sequence[Any], value: Any) -> bool:
        for item in observed:
            if item is None:
                continue
            if isinstance(value, bool) or isinstance(item, bool):
                if _as_bool(item) is not None and _as_bool(item) == _as_bool(value):
                    return True
                continue
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if _numeric(item) is not None and _numeric(item) == float(value):
                    return True
                continue
            text = str(item)
            pattern = str(value)
            if "contains" in self.modifiers:
                pattern = "*%s*" % pattern
            elif "startswith" in self.modifiers:
                pattern = "%s*" % pattern
            elif "endswith" in self.modifiers:
                pattern = "*%s" % pattern
            if _WILDCARD_RE.search(pattern):
                if glob_to_regex(pattern, case_sensitive=self.case_sensitive).match(text):
                    return True
            elif self._eq(text, pattern):
                return True
        return False

    def _eq(self, left: Any, right: Any) -> bool:
        if left is None or right is None:
            return left is right
        if self.case_sensitive:
            return str(left) == str(right)
        return str(left).lower() == str(right).lower()

    @staticmethod
    def _cidr_match(observed: Sequence[Any], network: Any) -> bool:
        for item in observed:
            try:
                if ipaddress.ip_address(str(item)) in network:
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _compare(observed: Sequence[Any], operator: str, value: Any) -> bool:
        threshold = _numeric(value)
        if threshold is None:
            return False
        for item in observed:
            number = _numeric(item)
            if number is None:
                continue
            if operator == "lt" and number < threshold:
                return True
            if operator == "lte" and number <= threshold:
                return True
            if operator == "gt" and number > threshold:
                return True
            if operator == "gte" and number >= threshold:
                return True
        return False


@dataclass
class KeywordMatcher:
    """A bare keyword search (a detection list without field names)."""

    values: Tuple[Any, ...]
    field: str = "*"
    modifiers: Tuple[str, ...] = ()

    def match(self, flat: Dict[str, Any]) -> bool:
        haystack = " ".join(
            str(value) for value in _iter_scalars(flat.values()) if value is not None
        ).lower()
        for value in self.values:
            pattern = str(value)
            if _WILDCARD_RE.search(pattern):
                if glob_to_regex("*%s*" % pattern.strip("*")).match(haystack):
                    return True
            elif pattern.lower() in haystack:
                return True
        return False


def _iter_scalars(values: Iterable[Any]) -> Iterable[Any]:
    for value in values:
        if isinstance(value, (list, tuple)):
            for item in value:
                yield item
        else:
            yield value


def _observed_values(flat: Dict[str, Any], field_name: str) -> List[Any]:
    """Read a (possibly multi-valued) field from a flattened event."""
    if field_name in flat:
        value = flat[field_name]
        return list(value) if isinstance(value, (list, tuple)) else [value]
    return []


def _numeric(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    return None
