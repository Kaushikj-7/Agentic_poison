"""Tests for AgentPOI-SDE controlled egress and transport security.

Verifies:
1. validate_transport_url enforces HTTPS for remote inference and permits HTTP strictly for loopback.
2. scrub_prompt_payload redacts multiline private keys, prefixed credential variables, and passwords.
3. scrub_repository_files redacts sensitive file types (.env*, *.pem, *.key, id_rsa*, etc.) and scrubs snippets.
"""

from __future__ import annotations

import pytest

from agentpoi_sde.agent.transport_security import (
    scrub_prompt_payload,
    scrub_repository_files,
    validate_transport_url,
)

# ---------------------------------------------------------------------------
# Suite 1: Transport URL Validation
# ---------------------------------------------------------------------------

def test_validate_transport_url_allows_https_remote() -> None:
    """Verify HTTPS endpoints for remote providers are permitted."""
    assert validate_transport_url("https://openrouter.ai/api/v1") == "https://openrouter.ai/api/v1"
    assert validate_transport_url("https://api.deepseek.com/v1") == "https://api.deepseek.com/v1"
    assert validate_transport_url("https://api.openai.com/v1/") == "https://api.openai.com/v1/"


def test_validate_transport_url_allows_loopback_http() -> None:
    """Verify HTTP is permitted strictly for local loopback inference."""
    assert validate_transport_url("http://localhost:8000/v1") == "http://localhost:8000/v1"
    assert validate_transport_url("http://127.0.0.1:8000/v1") == "http://127.0.0.1:8000/v1"
    assert validate_transport_url("http://127.0.0.1:11434") == "http://127.0.0.1:11434"
    assert validate_transport_url("http://[::1]:8000/v1") == "http://[::1]:8000/v1"


def test_validate_transport_url_rejects_remote_http() -> None:
    """Verify non-loopback HTTP endpoints are rejected fail-closed."""
    with pytest.raises(ValueError, match="Remote inference endpoints must use HTTPS"):
        validate_transport_url("http://openrouter.ai/api/v1")

    with pytest.raises(ValueError, match="Remote inference endpoints must use HTTPS"):
        validate_transport_url("http://api.deepseek.com/v1")

    with pytest.raises(ValueError, match="Remote inference endpoints must use HTTPS"):
        validate_transport_url("http://192.168.1.50:8000")

    with pytest.raises(ValueError, match="Remote inference endpoints must use HTTPS"):
        validate_transport_url("http://10.0.0.1:8000")

    with pytest.raises(ValueError, match="Remote inference endpoints must use HTTPS"):
        validate_transport_url("http://remote.local:8000")


def test_validate_transport_url_rejects_unsupported_schemes() -> None:
    """Verify non-HTTP(S) schemes are rejected fail-closed."""
    with pytest.raises(ValueError):
        validate_transport_url("ftp://localhost:8000")

    with pytest.raises(ValueError):
        validate_transport_url("file:///etc/passwd")

    with pytest.raises(ValueError):
        validate_transport_url("smb://server/share")

    with pytest.raises(ValueError):
        validate_transport_url("")

    with pytest.raises(ValueError):
        validate_transport_url("invalid-url")


# ---------------------------------------------------------------------------
# Suite 2: Prompt Payload Credential Scrubbing
# ---------------------------------------------------------------------------

def test_scrub_prompt_payload_redacts_multiline_rsa_private_key() -> None:
    """Verify multiline RSA private keys are redacted completely."""
    raw_prompt = (
        "Here is the deployment config:\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0m4w4k3j5z6k9l8v7x2y1a0b3c4d5e6f7g8h9i0j\n"
        "k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8\n"
        "-----END RSA PRIVATE KEY-----\n"
        "Please update the database connection."
    )
    scrubbed = scrub_prompt_payload(raw_prompt)
    assert "-----BEGIN RSA PRIVATE KEY-----" not in scrubbed
    assert "MIIEowIBAAKCAQEA0" not in scrubbed
    assert "-----END RSA PRIVATE KEY-----" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed
    assert "Please update the database connection." in scrubbed


def test_scrub_prompt_payload_redacts_openssh_and_ec_private_keys() -> None:
    """Verify OPENSSH and EC private keys are redacted."""
    raw_prompt = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
        "-----END OPENSSH PRIVATE KEY-----\n\n"
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIIDz7M5g9x7x8y9z0a1b2c3d4e5f6g7h8i9j0k1l2m3oAkBggqhkjOP\n"
        "-----END EC PRIVATE KEY-----\n"
    )
    scrubbed = scrub_prompt_payload(raw_prompt)
    assert "OPENSSH" not in scrubbed
    assert "b3BlbnNza" not in scrubbed
    assert "EC PRIVATE KEY" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed


def test_scrub_prompt_payload_redacts_prefixed_credential_variables() -> None:
    """Verify prefixed credential variable assignments are redacted completely."""
    raw = (
        "DEPLOY_API_KEY = 'sk-or-v1-abcdef1234567890'\n"
        "AWS_SECRET_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"
        "auth_token: Bearer_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
        "DB_PASSWORD = my_super_secret_db_pass_1234\n"
        "GITHUB_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'\n"
    )
    scrubbed = scrub_prompt_payload(raw)
    assert "sk-or-v1" not in scrubbed
    assert "wJalrXUtnFEMI" not in scrubbed
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in scrubbed
    assert "my_super_secret_db_pass_1234" not in scrubbed
    assert "ghp_1234567890" not in scrubbed
    # Ensure no ugly partial variable remains like DEPLOY_[REDACTED_SECRET]
    assert "DEPLOY_[REDACTED_SECRET]" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed


def test_scrub_prompt_payload_preserves_benign_code() -> None:
    """Verify benign source code without credentials is not altered."""
    code = (
        "def compute_discount(price: float, rate: float) -> float:\n"
        "    return price * (1.0 - rate)\n\n"
        "username = 'alice_smith'\n"
        "counter = 42\n"
    )
    scrubbed = scrub_prompt_payload(code)
    assert scrubbed == code


# ---------------------------------------------------------------------------
# Suite 3: Repository Files Scrubbing
# ---------------------------------------------------------------------------

def test_scrub_repository_files_redacts_sensitive_files() -> None:
    """Verify sensitive files by extension or pattern are replaced with redaction message."""
    files = {
        ".env": "DATABASE_URL=postgres://user:pass@localhost/db\nAPI_KEY=secret123\n",
        ".env.production": "SECRET_KEY=supersecret\n",
        "certs/server.pem": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n",
        "keys/private.key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
        "secrets/id_rsa": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB...\n",
        "secrets/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n",
        "config/app.p12": "binary_keystore_data",
        "src/main.py": "def main():\n    print('Hello world')\n",
        "src/config.py": "DEPLOY_API_KEY = 'sk-live-secret'\nDEBUG = True\n",
    }
    summary = scrub_repository_files(files)

    # Sensitive files redacted at file level
    assert "--- .env ---\n[REDACTED SENSITIVE FILE]" in summary
    assert "--- .env.production ---\n[REDACTED SENSITIVE FILE]" in summary
    assert "--- certs/server.pem ---\n[REDACTED SENSITIVE FILE]" in summary
    assert "--- keys/private.key ---\n[REDACTED SENSITIVE FILE]" in summary
    assert "--- secrets/id_rsa ---\n[REDACTED SENSITIVE FILE]" in summary
    assert "--- secrets/id_ed25519 ---\n[REDACTED SENSITIVE FILE]" in summary
    assert "--- config/app.p12 ---\n[REDACTED SENSITIVE FILE]" in summary

    # Sensitive contents never leaked
    assert "postgres://user:pass" not in summary
    assert "supersecret" not in summary
    assert "sk-live-secret" not in summary

    # Safe source code retained
    assert "--- src/main.py ---\ndef main():" in summary
    assert "--- src/config.py ---" in summary
    assert "DEBUG = True" in summary
    assert "[REDACTED_SECRET]" in summary
