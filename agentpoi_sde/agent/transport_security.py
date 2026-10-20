"""Transport security and sensitive egress scrubbing for AgentPOI-SDE.

Enforces transport-layer security invariants (Rule 10) and comprehensive
scrubbing of credentials, private keys, and sensitive configuration files
prior to transmitting any prompt or repository context to external LLM providers.
"""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

# Pattern matching multiline PEM / OpenSSH / EC private keys
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9_ -]+KEY-----[\s\S]*?-----END [A-Z0-9_ -]+KEY-----",
    re.MULTILINE,
)

# Pattern matching prefixed and unprefixed credential variables and assignments.
# Follows Rule 8: Never rely on \b preceding underscores (e.g. DEPLOY_API_KEY).
CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?:(?<=[^\w])|^)[\"']?[A-Za-z0-9_]*(?:api[_-]?key|secret|token|password|auth|private[_-]?key)[A-Za-z0-9_]*[\"']?\s*[:=]\s*(?:'[^'\r\n]*'|\"[^\"\r\n]*\"|[^\s,;\r\n]+)"
)

# Sensitive filename pattern covering environment files, private keys, certificates,
# SSH keys, and filenames with sensitive keyword substrings.
SENSITIVE_FILENAME_PATTERN = re.compile(
    r"(?:^|[/\\])(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|crt|cer)|id_(?:rsa|ed25519|ecdsa|dsa)(?:\..*)?)$|"
    r"(?:secret|credential|token|password|apikey|api_key)",
    re.IGNORECASE,
)

REDACTED_MARKER = "[REDACTED_SECRET]"
REDACTED_SECRET = REDACTED_MARKER
REDACTED_FILE = "[REDACTED SENSITIVE FILE]"


def validate_transport_url(base_url: str) -> str:
    """Validate remote provider endpoint URL fail-closed.

    Enforces HTTPS for remote providers. Allows HTTP strictly for local
    loopback addresses (localhost, 127.0.0.1, ::1).
    Raises ValueError for any remote HTTP or invalid/unsupported scheme.
    """
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("Provider base_url must be a non-empty string.")

    stripped = base_url.strip()
    parsed = urlparse(stripped)

    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid transport URL: {base_url!r}")

    scheme = parsed.scheme.lower()
    if scheme == "https":
        return stripped

    if scheme == "http":
        hostname = (parsed.hostname or "").lower()
        loopback_hosts = {"localhost", "127.0.0.1", "::1"}
        if hostname in loopback_hosts:
            return stripped
        raise ValueError(
            f"Remote inference endpoints must use HTTPS. Insecure HTTP is prohibited for remote host '{hostname}'."
        )

    raise ValueError(
        f"Unsupported transport scheme '{scheme}'. Only HTTPS (or HTTP for loopback) is permitted."
    )


def scrub_prompt_payload(text: str) -> str:
    """Scrub prompt payload, redacting private keys and credentials.

    Redacts multiline private keys (RSA, OPENSSH, EC) and credential variables
    (e.g. DEPLOY_API_KEY, AWS_SECRET_KEY, auth_token, passwords).
    Preserves benign text and code structures.
    """
    if not text:
        return text

    # Step 1: Redact multiline private key blocks
    scrubbed = PRIVATE_KEY_PATTERN.sub(REDACTED_SECRET, text)

    # Step 2: Redact prefixed and standard credential assignments
    scrubbed = CREDENTIAL_PATTERN.sub(REDACTED_SECRET, scrubbed)

    return scrubbed


def scrub_repository_files(files: Dict[str, str], per_file_chars: int = 400) -> str:
    """Summarise repository files safely for remote LLM context.

    Redacts sensitive files entirely (.env*, *.pem, *.key, *.p12, id_rsa*, etc.)
    and scrubs credentials from file snippets within the allowed character budget.
    """
    if not files:
        return ""

    lines: List[str] = []
    for path in sorted(files.keys()):
        normalized = path.replace("\\", "/")
        if SENSITIVE_FILENAME_PATTERN.search(normalized):
            lines.append(f"--- {path} ---\n{REDACTED_FILE}")
            continue

        content = files[path]
        snippet = content[:per_file_chars].replace("\r", "")
        scrubbed_snippet = scrub_prompt_payload(snippet)
        lines.append(f"--- {path} ---\n{scrubbed_snippet}")

    return "\n".join(lines)
