"""Legacy pattern scanner and multi-language vulnerability detector.

Detects high-risk legacy PHP vulnerabilities, webshell backdoors, and Python
unsafe deserialization patterns. Operates 100% locally on standard CPU via pure
regex and text parsing without ever importing, compiling, executing, or
running scanned source files.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext, ScanResult

SCANNER_NAME = "legacy_patterns"

# Supported language extensions
PHP_EXTENSIONS: Set[str] = {".php", ".phtml", ".php3", ".php4", ".php5", ".inc"}
PYTHON_EXTENSIONS: Set[str] = {".py"}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingCategory(str, Enum):
    VULNERABILITY = "sast"
    MALICIOUS_CODE = "malware"


# ------------------------------------------------------------------------------
# Pattern Definitions
# ------------------------------------------------------------------------------

# Superglobals that indicate user-controlled input in PHP
PHP_USER_INPUT_RE = re.compile(
    r"\$(?:_GET|_POST|_REQUEST|_COOKIE|_SERVER)\b", re.IGNORECASE
)

# 1. PHP SQL Injection Patterns
PHP_SQLI_CALL_RE = re.compile(
    r"""(?<![a-zA-Z0-9_\$])(?:mysqli_query|mysql_query|mysqli_real_query|mysqli_multi_query|pg_query|sqlite_query|\$(?:pdo|db|conn|connection|this->db|this->pdo|mysqli)\s*->\s*(?:query|prepare|exec))\s*\(([\s\S]*?)\)""",
    re.IGNORECASE,
)

PHP_SQLI_ASSIGN_RE = re.compile(
    r"""\$(?:sql|query|stmt|sql_query|query_string)\s*\.?=\s*["']\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|DROP\s+TABLE|ALTER\s+TABLE)\b([\s\S]*?);""",
    re.IGNORECASE,
)

PHP_CONCAT_OR_VAR_RE = re.compile(
    r"""(?:\.\s*\$|\$\w+\s*\.|\{\$(?:_GET|_POST|_REQUEST|_COOKIE|\w+).*?\}|\$(?:_GET|_POST|_REQUEST|_COOKIE)\b|["']\s*\.\s*\$|\bWHERE\b.*?\$[a-zA-Z_\x80-\xff])""",
    re.IGNORECASE,
)

# 2. PHP Command Execution / Injection Patterns
PHP_EXEC_CALL_RE = re.compile(
    r"""(?<![a-zA-Z0-9_\$>\-])(?:exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(([\s\S]*?)\)""",
    re.IGNORECASE,
)

PHP_BACKTICK_RE = re.compile(
    r"""`([^`\n]*\$(?:_GET|_POST|_REQUEST|_COOKIE|\w+)[^`\n]*)`""",
    re.IGNORECASE,
)

# 3. PHP Unsafe Deserialization
PHP_UNSERIALIZE_RE = re.compile(
    r"""(?<![a-zA-Z0-9_\$])unserialize\s*\(([\s\S]*?)\)""",
    re.IGNORECASE,
)
PHP_ALLOWED_CLASSES_FALSE_RE = re.compile(
    r"""['"]allowed_classes['"]\s*=>\s*false""",
    re.IGNORECASE,
)

# 4. PHP Obfuscated Eval & Webshell Backdoors
PHP_EVAL_DECODE_RE = re.compile(
    r"""@?eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack)\s*\(""",
    re.IGNORECASE,
)
PHP_ASSERT_DECODE_RE = re.compile(
    r"""@?assert\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack)\s*\(""",
    re.IGNORECASE,
)
PHP_EVAL_SUPERGLOBAL_RE = re.compile(
    r"""@?eval\s*\(\s*\$(?:_POST|_GET|_REQUEST|_COOKIE|GLOBALS)\s*\[""",
    re.IGNORECASE,
)
PHP_ASSERT_SUPERGLOBAL_RE = re.compile(
    r"""@?assert\s*\(\s*\$(?:_POST|_GET|_REQUEST|_COOKIE|GLOBALS)\s*\[""",
    re.IGNORECASE,
)
PHP_EVAL_VAR_RE = re.compile(
    r"""@?eval\s*\(\s*\$[a-zA-Z_\x80-\xff]""",
    re.IGNORECASE,
)
PHP_PREG_REPLACE_E_RE = re.compile(
    r"""preg_replace\s*\(\s*['\"][^'\"]*\/[a-zA-Z]*e[a-zA-Z]*['\"]\s*,""",
    re.IGNORECASE,
)
PHP_DYNAMIC_FUNCTION_DISPATCH_RE = re.compile(
    r"""(?:\$(?:_POST|_GET|_REQUEST|_COOKIE)\[[^\]]+\]\s*\(|\$[a-zA-Z0-9_]+\s*=\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\[[^\]]+\];\s*\$[a-zA-Z0-9_]+\s*\()""",
    re.IGNORECASE,
)
PHP_CREATE_FUNCTION_RE = re.compile(
    r"""(?<![a-zA-Z0-9_\$])create_function\s*\(""",
    re.IGNORECASE,
)

# 5. Python Deserialization Risks
PY_PICKLE_RE = re.compile(
    r"""(?<![a-zA-Z0-9_])(?:pickle|_pickle|cPickle)\s*\.\s*(?:loads?|Unpickler)\s*\(""",
)
PY_YAML_UNSAFE_LOAD_RE = re.compile(
    r"""yaml\s*\.\s*unsafe_load\s*\(""",
)
PY_YAML_LOAD_RE = re.compile(
    r"""yaml\s*\.\s*load\s*\(([\s\S]*?)\)""",
)
PY_YAML_SAFE_LOADER_RE = re.compile(
    r"""Loader\s*=\s*(?:yaml\.)?(?:SafeLoader|CSafeLoader|BaseLoader|FullLoader)""",
)
PY_TORCH_LOAD_RE = re.compile(
    r"""torch\s*\.\s*load\s*\(([\s\S]*?)\)""",
)
PY_TORCH_WEIGHTS_ONLY_TRUE_RE = re.compile(
    r"""weights_only\s*=\s*True""",
)
PY_SHELVE_OPEN_RE = re.compile(
    r"""shelve\s*\.\s*open\s*\(""",
)


class LegacyPatternScanner:
    """Deterministic, parse/regex-only multi-language vulnerability scanner.

    Implements the Scanner protocol (Zone 2) with zero host execution guarantees.
    """

    name = SCANNER_NAME

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = dict(config or {})

    def run(self, context: ScanContext) -> ScanResult:
        """Runs scan over all indexed files in the ScanContext."""
        findings: List[Finding] = []
        for relpath in context.file_index:
            ext = Path(relpath).suffix.lower()
            if ext not in PHP_EXTENSIONS and ext not in PYTHON_EXTENSIONS:
                continue
            code = context.read_text(relpath)
            if code is None:
                continue
            file_findings = self._scan_content(code, rel_path=relpath)
            for f in file_findings:
                f.commit_sha = context.commit_sha
            findings.extend(file_findings)

        return ScanResult(scanner=self.name, findings=findings)

    def scan_file(self, file_path: Path | str, rel_path: Optional[str] = None) -> List[Finding]:
        """Scans a single file on disk in a zero-execution manner."""
        path = Path(file_path)
        rel = rel_path or path.name
        ext = path.suffix.lower()
        if ext not in PHP_EXTENSIONS and ext not in PYTHON_EXTENSIONS:
            return []
        if not path.is_file():
            return []
        try:
            # Safe read: limit to 1MB, decode as utf-8 replacing errors
            raw_data = path.read_bytes()[:1_000_000]
            code = raw_data.decode("utf-8", errors="replace")
        except OSError:
            return []
        return self._scan_content(code, rel_path=rel)

    def scan_directory(self, target_dir: Path | str) -> List[Finding]:
        """Scans all eligible files in a directory recursively without executing any."""
        root = Path(target_dir)
        findings: List[Finding] = []
        if not root.is_dir():
            return []

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            # Skip .git or nested virtual environments
            if any(part.startswith(".") and part != "." for part in p.parts):
                continue
            ext = p.suffix.lower()
            if ext in PHP_EXTENSIONS or ext in PYTHON_EXTENSIONS:
                rel = str(p.relative_to(root)).replace("\\", "/")
                findings.extend(self.scan_file(p, rel_path=rel))

        return findings

    # --------------------------------------------------------------------------
    # Content Scanning Logic
    # --------------------------------------------------------------------------

    def _scan_content(self, code: str, rel_path: str) -> List[Finding]:
        findings: List[Finding] = []
        ext = Path(rel_path).suffix.lower()

        if ext in PHP_EXTENSIONS:
            findings.extend(self._scan_php_content(code, rel_path))
        elif ext in PYTHON_EXTENSIONS:
            findings.extend(self._scan_python_content(code, rel_path))

        return findings

    def _scan_php_content(self, code: str, rel_path: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.splitlines()

        # Track reported (rule_id, line_number) to prevent duplicate reports per line
        reported: Set[tuple[str, int]] = set()

        def add_finding(
            rule_id: str,
            line_num: int,
            title: str,
            detail: str,
            severity: str,
            category: str,
            confidence: float,
            maliciousness: float,
            vulnerability: float,
            snippet: str,
        ) -> None:
            key = (rule_id, line_num)
            if key in reported:
                return
            reported.add(key)
            cleaned_snippet = snippet.strip()[:300]
            finding = Finding(
                file=rel_path,
                lines=[line_num],
                category=category,
                severity=severity,
                title=title,
                detail=detail,
                scanner=self.name,
                confidence=confidence,
                maliciousness=maliciousness,
                vulnerability=vulnerability,
                evidence=[
                    {
                        "kind": "scanner_output",
                        "rule_id": rule_id,
                        "text": cleaned_snippet,
                    }
                ],
            )
            # Attach interface attributes
            finding.rule_id = rule_id
            finding.file_path = rel_path
            finding.line_number = line_num
            finding.snippet = cleaned_snippet
            finding.description = detail
            findings.append(finding)

        # ----------------------------------------------------------------------
        # Check PHP Obfuscated Eval & Webshell Backdoors
        # ----------------------------------------------------------------------
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if self._is_php_comment(stripped):
                continue
            code_line = self._strip_php_inline_comment(line)

            if PHP_EVAL_DECODE_RE.search(code_line):
                add_finding(
                    rule_id="legacy.php.obfuscated_eval",
                    line_num=lineno,
                    title="PHP obfuscated eval with decoding function",
                    detail=f"Line {lineno} invokes eval() with payload decoding functions (base64/gzinflate/str_rot13). High-probability webshell backdoor.",
                    severity=Severity.CRITICAL.value,
                    category=FindingCategory.MALICIOUS_CODE.value,
                    confidence=0.98,
                    maliciousness=0.95,
                    vulnerability=0.85,
                    snippet=line,
                )
            elif PHP_ASSERT_DECODE_RE.search(code_line):
                add_finding(
                    rule_id="legacy.php.obfuscated_eval",
                    line_num=lineno,
                    title="PHP obfuscated assert with decoding function",
                    detail=f"Line {lineno} executes assert() on decoded payload. Obfuscated code execution vector.",
                    severity=Severity.CRITICAL.value,
                    category=FindingCategory.MALICIOUS_CODE.value,
                    confidence=0.98,
                    maliciousness=0.95,
                    vulnerability=0.85,
                    snippet=line,
                )
            elif PHP_EVAL_SUPERGLOBAL_RE.search(code_line):
                add_finding(
                    rule_id="legacy.php.obfuscated_eval",
                    line_num=lineno,
                    title="PHP direct eval of user superglobal",
                    detail=f"Line {lineno} passes user-controlled superglobal ($_POST/$_GET/$_REQUEST) directly into eval(). Definite webshell backdoor.",
                    severity=Severity.CRITICAL.value,
                    category=FindingCategory.MALICIOUS_CODE.value,
                    confidence=0.99,
                    maliciousness=0.98,
                    vulnerability=0.90,
                    snippet=line,
                )
            elif PHP_ASSERT_SUPERGLOBAL_RE.search(code_line):
                add_finding(
                    rule_id="legacy.php.obfuscated_eval",
                    line_num=lineno,
                    title="PHP direct assert of user superglobal",
                    detail=f"Line {lineno} passes user-controlled superglobal directly into assert(). Classic PHP webshell pattern.",
                    severity=Severity.CRITICAL.value,
                    category=FindingCategory.MALICIOUS_CODE.value,
                    confidence=0.99,
                    maliciousness=0.98,
                    vulnerability=0.90,
                    snippet=line,
                )
            elif PHP_PREG_REPLACE_E_RE.search(code_line):
                add_finding(
                    rule_id="legacy.php.obfuscated_eval",
                    line_num=lineno,
                    title="PHP preg_replace /e modifier arbitrary execution",
                    detail=f"Line {lineno} uses deprecated /e eval modifier in preg_replace, allowing code execution.",
                    severity=Severity.CRITICAL.value,
                    category=FindingCategory.MALICIOUS_CODE.value,
                    confidence=0.95,
                    maliciousness=0.90,
                    vulnerability=0.90,
                    snippet=line,
                )
            elif PHP_DYNAMIC_FUNCTION_DISPATCH_RE.search(code_line):
                add_finding(
                    rule_id="legacy.php.obfuscated_eval",
                    line_num=lineno,
                    title="PHP dynamic function invocation from superglobal",
                    detail=f"Line {lineno} dynamically executes a function named in user superglobals. Webshell backdoor vector.",
                    severity=Severity.CRITICAL.value,
                    category=FindingCategory.MALICIOUS_CODE.value,
                    confidence=0.95,
                    maliciousness=0.95,
                    vulnerability=0.85,
                    snippet=line,
                )
            elif PHP_CREATE_FUNCTION_RE.search(code_line):
                add_finding(
                    rule_id="legacy.php.obfuscated_eval",
                    line_num=lineno,
                    title="PHP create_function arbitrary execution",
                    detail=f"Line {lineno} calls create_function() which evaluates string arguments as runtime code.",
                    severity=Severity.CRITICAL.value,
                    category=FindingCategory.MALICIOUS_CODE.value,
                    confidence=0.90,
                    maliciousness=0.85,
                    vulnerability=0.80,
                    snippet=line,
                )
            elif PHP_EVAL_VAR_RE.search(code_line):
                add_finding(
                    rule_id="legacy.php.obfuscated_eval",
                    line_num=lineno,
                    title="PHP dynamic eval expression",
                    detail=f"Line {lineno} calls eval() on variable expression.",
                    severity=Severity.CRITICAL.value,
                    category=FindingCategory.MALICIOUS_CODE.value,
                    confidence=0.90,
                    maliciousness=0.85,
                    vulnerability=0.80,
                    snippet=line,
                )

        # ----------------------------------------------------------------------
        # Check PHP Command Execution / Injection
        # ----------------------------------------------------------------------
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if self._is_php_comment(stripped):
                continue
            code_line = self._strip_php_inline_comment(line)

            # Check backticks first
            backtick_match = PHP_BACKTICK_RE.search(code_line)
            if backtick_match:
                has_user = bool(PHP_USER_INPUT_RE.search(backtick_match.group(1)))
                sev = Severity.CRITICAL.value if has_user else Severity.HIGH.value
                add_finding(
                    rule_id="legacy.php.command_injection",
                    line_num=lineno,
                    title="PHP backtick operator command execution",
                    detail=f"Line {lineno} executes shell commands via backtick operator with dynamic input.",
                    severity=sev,
                    category=FindingCategory.VULNERABILITY.value,
                    confidence=0.95,
                    maliciousness=0.8 if has_user else 0.3,
                    vulnerability=0.95,
                    snippet=line,
                )

            # Check function execution calls
            exec_match = PHP_EXEC_CALL_RE.search(code_line)
            if exec_match:
                args = exec_match.group(1).strip()
                has_user = bool(PHP_USER_INPUT_RE.search(args))
                sev = Severity.CRITICAL.value if has_user else Severity.HIGH.value
                add_finding(
                    rule_id="legacy.php.command_injection",
                    line_num=lineno,
                    title="PHP dangerous system command execution",
                    detail=f"Line {lineno} invokes dangerous command execution function ({exec_match.group(0).split('(')[0].strip()}). Command injection risk.",
                    severity=sev,
                    category=FindingCategory.VULNERABILITY.value,
                    confidence=0.95,
                    maliciousness=0.8 if has_user else 0.3,
                    vulnerability=0.95,
                    snippet=line,
                )

        # ----------------------------------------------------------------------
        # Check PHP Unsafe Deserialization
        # ----------------------------------------------------------------------
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if self._is_php_comment(stripped):
                continue
            code_line = self._strip_php_inline_comment(line)

            unserialize_match = PHP_UNSERIALIZE_RE.search(code_line)
            if unserialize_match:
                args = unserialize_match.group(1)
                if not PHP_ALLOWED_CLASSES_FALSE_RE.search(args):
                    has_user = bool(PHP_USER_INPUT_RE.search(args))
                    sev = Severity.CRITICAL.value if has_user else Severity.HIGH.value
                    add_finding(
                        rule_id="legacy.php.deserialization",
                        line_num=lineno,
                        title="PHP unsafe object deserialization",
                        detail=f"Line {lineno} calls unserialize() without 'allowed_classes => false'. Vulnerable to PHP Object Injection / POP chains.",
                        severity=sev,
                        category=FindingCategory.VULNERABILITY.value,
                        confidence=0.92,
                        maliciousness=0.6 if has_user else 0.2,
                        vulnerability=0.90,
                        snippet=line,
                    )

        # ----------------------------------------------------------------------
        # Check PHP SQL Injection
        # ----------------------------------------------------------------------
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if self._is_php_comment(stripped):
                continue
            code_line = self._strip_php_inline_comment(line)

            # Check query calls
            call_match = PHP_SQLI_CALL_RE.search(code_line)
            if call_match:
                args = call_match.group(1)
                # Verify whether the arguments concatenate variables or interpolate
                if PHP_CONCAT_OR_VAR_RE.search(args):
                    has_user = bool(PHP_USER_INPUT_RE.search(args))
                    sev = Severity.CRITICAL.value if has_user else Severity.HIGH.value
                    add_finding(
                        rule_id="legacy.php.sqli",
                        line_num=lineno,
                        title="PHP SQL injection in database query call",
                        detail=f"Line {lineno} passes concatenated or interpolated query string to database function. SQL injection vulnerability.",
                        severity=sev,
                        category=FindingCategory.VULNERABILITY.value,
                        confidence=0.92,
                        maliciousness=0.5 if has_user else 0.1,
                        vulnerability=0.95,
                        snippet=line,
                    )

            # Check SQL string variable assignments with concatenation / variables
            assign_match = PHP_SQLI_ASSIGN_RE.search(code_line)
            if assign_match:
                clause = assign_match.group(1)
                if PHP_CONCAT_OR_VAR_RE.search(clause) or PHP_USER_INPUT_RE.search(code_line):
                    has_user = bool(PHP_USER_INPUT_RE.search(code_line))
                    sev = Severity.CRITICAL.value if has_user else Severity.HIGH.value
                    add_finding(
                        rule_id="legacy.php.sqli",
                        line_num=lineno,
                        title="PHP SQL query string concatenated with dynamic input",
                        detail=f"Line {lineno} constructs SQL statement via variable concatenation or interpolation.",
                        severity=sev,
                        category=FindingCategory.VULNERABILITY.value,
                        confidence=0.90,
                        maliciousness=0.5 if has_user else 0.1,
                        vulnerability=0.95,
                        snippet=line,
                    )

        # ----------------------------------------------------------------------
        # Multi-Line Statement Scanning Pass
        # ----------------------------------------------------------------------
        # Strip comments while preserving exact line positions
        cleaned_code = re.sub(
            r"/\*[\s\S]*?\*/",
            lambda m: "\n" * m.group(0).count("\n"),
            code,
        )
        cleaned_code = re.sub(r"(?<!:)//[^\n]*", "", cleaned_code)
        cleaned_code = re.sub(r"#[^\n]*", "", cleaned_code)

        # Multi-line exec/system/passthru/shell_exec calls
        for m in PHP_EXEC_CALL_RE.finditer(cleaned_code):
            start = m.start()
            lineno = cleaned_code[:start].count("\n") + 1
            args = m.group(1).strip()
            has_user = bool(PHP_USER_INPUT_RE.search(args))
            sev = Severity.CRITICAL.value if has_user else Severity.HIGH.value
            snippet = code[start : m.end()].strip()
            fn_name = m.group(0).split("(")[0].strip()
            add_finding(
                rule_id="legacy.php.command_injection",
                line_num=lineno,
                title="PHP dangerous system command execution",
                detail=f"Line {lineno} invokes dangerous command execution function ({fn_name}). Command injection risk.",
                severity=sev,
                category=FindingCategory.VULNERABILITY.value,
                confidence=0.95,
                maliciousness=0.8 if has_user else 0.3,
                vulnerability=0.95,
                snippet=snippet,
            )

        # Multi-line SQLi query calls
        for m in PHP_SQLI_CALL_RE.finditer(cleaned_code):
            start = m.start()
            lineno = cleaned_code[:start].count("\n") + 1
            args = m.group(1)
            if PHP_CONCAT_OR_VAR_RE.search(args):
                has_user = bool(PHP_USER_INPUT_RE.search(args))
                sev = Severity.CRITICAL.value if has_user else Severity.HIGH.value
                snippet = code[start : m.end()].strip()
                add_finding(
                    rule_id="legacy.php.sqli",
                    line_num=lineno,
                    title="PHP SQL injection in database query call",
                    detail=f"Line {lineno} passes concatenated or interpolated query string to database function. SQL injection vulnerability.",
                    severity=sev,
                    category=FindingCategory.VULNERABILITY.value,
                    confidence=0.92,
                    maliciousness=0.5 if has_user else 0.1,
                    vulnerability=0.95,
                    snippet=snippet,
                )

        # Multi-line SQLi variable assignments
        for m in PHP_SQLI_ASSIGN_RE.finditer(cleaned_code):
            start = m.start()
            lineno = cleaned_code[:start].count("\n") + 1
            clause = m.group(1)
            full_stmt = m.group(0)
            if PHP_CONCAT_OR_VAR_RE.search(clause) or PHP_USER_INPUT_RE.search(full_stmt):
                has_user = bool(PHP_USER_INPUT_RE.search(full_stmt))
                sev = Severity.CRITICAL.value if has_user else Severity.HIGH.value
                snippet = code[start : m.end()].strip()
                add_finding(
                    rule_id="legacy.php.sqli",
                    line_num=lineno,
                    title="PHP SQL query string concatenated with dynamic input",
                    detail=f"Line {lineno} constructs SQL statement via variable concatenation or interpolation.",
                    severity=sev,
                    category=FindingCategory.VULNERABILITY.value,
                    confidence=0.90,
                    maliciousness=0.5 if has_user else 0.1,
                    vulnerability=0.95,
                    snippet=snippet,
                )

        # Multi-line unserialize calls
        for m in PHP_UNSERIALIZE_RE.finditer(cleaned_code):
            start = m.start()
            lineno = cleaned_code[:start].count("\n") + 1
            args = m.group(1)
            if not PHP_ALLOWED_CLASSES_FALSE_RE.search(args):
                has_user = bool(PHP_USER_INPUT_RE.search(args))
                sev = Severity.CRITICAL.value if has_user else Severity.HIGH.value
                snippet = code[start : m.end()].strip()
                add_finding(
                    rule_id="legacy.php.deserialization",
                    line_num=lineno,
                    title="PHP unsafe object deserialization",
                    detail=f"Line {lineno} calls unserialize() without 'allowed_classes => false'. Vulnerable to PHP Object Injection / POP chains.",
                    severity=sev,
                    category=FindingCategory.VULNERABILITY.value,
                    confidence=0.92,
                    maliciousness=0.6 if has_user else 0.2,
                    vulnerability=0.90,
                    snippet=snippet,
                )

        # Multi-line obfuscated eval
        for m in PHP_EVAL_DECODE_RE.finditer(cleaned_code):
            start = m.start()
            lineno = cleaned_code[:start].count("\n") + 1
            snippet = code[start : m.end() + 50].strip()
            add_finding(
                rule_id="legacy.php.obfuscated_eval",
                line_num=lineno,
                title="PHP obfuscated eval with decoding function",
                detail=f"Line {lineno} invokes eval() with payload decoding functions (base64/gzinflate/str_rot13). High-probability webshell backdoor.",
                severity=Severity.CRITICAL.value,
                category=FindingCategory.MALICIOUS_CODE.value,
                confidence=0.98,
                maliciousness=0.95,
                vulnerability=0.85,
                snippet=snippet,
            )

        return findings

    def _scan_python_content(self, code: str, rel_path: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.splitlines()

        reported: Set[tuple[str, int]] = set()

        def add_finding(
            rule_id: str,
            line_num: int,
            title: str,
            detail: str,
            severity: str,
            category: str,
            confidence: float,
            maliciousness: float,
            vulnerability: float,
            snippet: str,
        ) -> None:
            key = (rule_id, line_num)
            if key in reported:
                return
            reported.add(key)
            cleaned_snippet = snippet.strip()[:300]
            finding = Finding(
                file=rel_path,
                lines=[line_num],
                category=category,
                severity=severity,
                title=title,
                detail=detail,
                scanner=self.name,
                confidence=confidence,
                maliciousness=maliciousness,
                vulnerability=vulnerability,
                evidence=[
                    {
                        "kind": "scanner_output",
                        "rule_id": rule_id,
                        "text": cleaned_snippet,
                    }
                ],
            )
            finding.rule_id = rule_id
            finding.file_path = rel_path
            finding.line_number = line_num
            finding.snippet = cleaned_snippet
            finding.description = detail
            findings.append(finding)

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            code_line = line.split("#")[0]

            # 1. Pickle load / loads
            if PY_PICKLE_RE.search(code_line):
                add_finding(
                    rule_id="agentic.python.deserialization",
                    line_num=lineno,
                    title="Python unsafe pickle deserialization",
                    detail=f"Line {lineno} calls pickle deserialization which allows arbitrary code execution via __reduce__.",
                    severity=Severity.HIGH.value,
                    category=FindingCategory.VULNERABILITY.value,
                    confidence=0.92,
                    maliciousness=0.2,
                    vulnerability=0.88,
                    snippet=line,
                )

            # 2. yaml.unsafe_load
            elif PY_YAML_UNSAFE_LOAD_RE.search(code_line):
                add_finding(
                    rule_id="agentic.python.deserialization",
                    line_num=lineno,
                    title="Python unsafe YAML deserialization",
                    detail=f"Line {lineno} calls yaml.unsafe_load() allowing arbitrary Python object instantiation.",
                    severity=Severity.HIGH.value,
                    category=FindingCategory.VULNERABILITY.value,
                    confidence=0.95,
                    maliciousness=0.2,
                    vulnerability=0.90,
                    snippet=line,
                )

            # 3. yaml.load without SafeLoader
            elif PY_YAML_LOAD_RE.search(code_line):
                match = PY_YAML_LOAD_RE.search(code_line)
                args = match.group(1) if match else ""
                if not PY_YAML_SAFE_LOADER_RE.search(args):
                    add_finding(
                        rule_id="agentic.python.deserialization",
                        line_num=lineno,
                        title="Python yaml.load without safe loader",
                        detail=f"Line {lineno} invokes yaml.load() without SafeLoader. Arbitrary object execution risk.",
                        severity=Severity.HIGH.value,
                        category=FindingCategory.VULNERABILITY.value,
                        confidence=0.88,
                        maliciousness=0.2,
                        vulnerability=0.85,
                        snippet=line,
                    )

            # 4. torch.load without weights_only=True
            elif PY_TORCH_LOAD_RE.search(code_line):
                match = PY_TORCH_LOAD_RE.search(code_line)
                args = match.group(1) if match else ""
                if not PY_TORCH_WEIGHTS_ONLY_TRUE_RE.search(args):
                    add_finding(
                        rule_id="agentic.python.deserialization",
                        line_num=lineno,
                        title="Python torch.load without weights_only=True",
                        detail=f"Line {lineno} loads PyTorch checkpoint without weights_only=True, allowing arbitrary pickle execution.",
                        severity=Severity.HIGH.value,
                        category=FindingCategory.VULNERABILITY.value,
                        confidence=0.85,
                        maliciousness=0.2,
                        vulnerability=0.85,
                        snippet=line,
                    )

            # 5. shelve.open
            elif PY_SHELVE_OPEN_RE.search(code_line):
                add_finding(
                    rule_id="agentic.python.deserialization",
                    line_num=lineno,
                    title="Python shelve storage deserialization risk",
                    detail=f"Line {lineno} opens a shelve database which unpickles stored data.",
                    severity=Severity.HIGH.value,
                    category=FindingCategory.VULNERABILITY.value,
                    confidence=0.80,
                    maliciousness=0.2,
                    vulnerability=0.80,
                    snippet=line,
                )

        return findings

    # --------------------------------------------------------------------------
    # Comment Helpers
    # --------------------------------------------------------------------------

    @staticmethod
    def _is_php_comment(stripped_line: str) -> bool:
        return (
            stripped_line.startswith("//")
            or stripped_line.startswith("#")
            or stripped_line.startswith("/*")
            or stripped_line.startswith("*")
        )

    @staticmethod
    def _strip_php_inline_comment(line: str) -> str:
        # Strip // comments only when not preceded by : (preserves http:// and https://)
        line = re.sub(r"(?<!:)//.*$", "", line)
        if "#" in line:
            line = line.split("#")[0]
        return line
