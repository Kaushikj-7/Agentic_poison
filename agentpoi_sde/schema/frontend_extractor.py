"""Extractor for API client calls in frontend source files."""

from __future__ import annotations

import re
from typing import List

from agentpoi_sde.schema.contract_model import FrontendCall, HTTPMethod


class FrontendCallExtractor:
    """Extracts HTTP API calls from frontend JavaScript, TypeScript, or Python clients."""

    # Matches axios.<method>('path' or `/path/${id}`, { key1: val, key2: val })
    AXIOS_PATTERN = re.compile(
        r"""axios\.(get|post|put|delete|patch)\s*\(\s*[`'"]([^`'"]+)[`'"](?:\s*,\s*(\{([^}]+)\}))?""",
        re.IGNORECASE | re.DOTALL,
    )

    # Matches fetch('path' or `/path/${id}`, { method: 'POST', ... })
    FETCH_PATTERN = re.compile(
        r"""fetch\s*\(\s*[`'"]([^`'"]+)[`'"](?:\s*,\s*\{([^}]+)\})?""",
        re.IGNORECASE | re.DOTALL,
    )

    def extract_calls(self, file_path: str, source_code: str) -> List[FrontendCall]:
        """Extracts all API client calls detected in the given source code."""
        calls: List[FrontendCall] = []
        self._extract_axios_calls(calls, file_path, source_code)
        self._extract_fetch_calls(calls, file_path, source_code)
        return calls

    def _extract_axios_calls(self, calls: List[FrontendCall], file_path: str, source_code: str) -> None:
        """Extracts axios.get/post/put/delete/patch invocations."""
        for match in self.AXIOS_PATTERN.finditer(source_code):
            method_str = match.group(1).upper()
            raw_path = match.group(2)
            body_block = match.group(4) or ""

            method = HTTPMethod[method_str] if method_str in HTTPMethod.__members__ else HTTPMethod.GET
            payload_keys = self._parse_object_keys(body_block)
            line = source_code[: match.start()].count("\n") + 1

            calls.append(
                FrontendCall(
                    method=method,
                    raw_path=raw_path,
                    payload_keys=payload_keys,
                    file_path=file_path,
                    line=line,
                )
            )

    def _extract_fetch_calls(self, calls: List[FrontendCall], file_path: str, source_code: str) -> None:
        """Extracts fetch() invocations with options block."""
        for match in self.FETCH_PATTERN.finditer(source_code):
            raw_path = match.group(1)
            options_block = match.group(2) or ""

            method = HTTPMethod.GET
            method_match = re.search(r"""method\s*:\s*['"]([A-Za-z]+)['"]""", options_block)
            if method_match:
                m_upper = method_match.group(1).upper()
                if m_upper in HTTPMethod.__members__:
                    method = HTTPMethod[m_upper]

            payload_keys = self._parse_fetch_body_keys(options_block)
            line = source_code[: match.start()].count("\n") + 1

            calls.append(
                FrontendCall(
                    method=method,
                    raw_path=raw_path,
                    payload_keys=payload_keys,
                    file_path=file_path,
                    line=line,
                )
            )

    def _parse_object_keys(self, obj_literal: str) -> List[str]:
        """Extracts top-level property keys from an object literal string,
        supporting multiline, single-line, and ES6 shorthand notations."""
        if not obj_literal:
            return []
        keys: List[str] = []
        # Strip nested braces and brackets to isolate top-level keys
        cleaned = re.sub(r"\{[^{}]*\}", "", obj_literal)
        cleaned = re.sub(r"\[[^\[\]]*\]", "", cleaned)

        for part in cleaned.split(","):
            item = part.strip()
            if not item:
                continue
            # Handle key: value or "key": value
            m_kv = re.match(r"^['\"]?([a-zA-Z0-9_]+)['\"]?\s*:", item)
            if m_kv:
                keys.append(m_kv.group(1))
                continue
            # Handle ES6 shorthand property: { payee_id, amount }
            m_short = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)$", item)
            if m_short:
                keys.append(m_short.group(1))
        return keys

    def _parse_fetch_body_keys(self, options_block: str) -> List[str]:
        """Extracts JSON.stringify keys from a fetch options body."""
        body_match = re.search(r"""body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]+)\}\s*\)""", options_block)
        if body_match:
            return self._parse_object_keys(body_match.group(1))
        return []
