"""Domain Isolation Invariance Tests.

Enforces strict domain isolation between:
1. Financial & Transactional Agent (`agent_poi`):
   Wire disbursements, invoice verification, escrow settlement, and ledger reconciliation.
2. Software-Engineering Agent (`agentpoi_sde`):
   AST symbol index, immutable repo state anchor, seven sink invariants, and DevGuard.

Validates that configuration loaders, environment variables, and helper functions
never bleed configuration or state across domain boundaries.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from agent_poi.core.config_loader import (
    get_financial_domain_config,
    get_trust_model_config,
    load_config,
)
from agentpoi_sde.config_loader import (
    get_egress_allowlist,
    get_invariant_config,
    get_protected_paths,
    get_test_markers,
    load_sde_config,
)


@pytest.fixture(autouse=True)
def _clear_config_caches() -> None:
    """Ensure LRU caches on config loaders are clean before and after each test."""
    load_config.cache_clear()
    load_sde_config.cache_clear()
    yield
    load_config.cache_clear()
    load_sde_config.cache_clear()


class TestSdeConfigIsolation:
    """Verify SDE configuration loader enforces domain isolation."""

    def test_sde_config_loads_sde_keys(self) -> None:
        """Verify load_sde_config populates all expected SDE domain keys."""
        cfg: Dict[str, Any] = load_sde_config()
        assert "invariants" in cfg
        assert "guard" in cfg
        assert "egress_allowlist" in cfg
        assert "protected_paths" in cfg
        assert "test_markers" in cfg
        assert "runtime" in cfg

        # Verify invariant toggle dictionary has all 7 sink invariants
        invariants = cfg["invariants"]
        expected_invariants = {
            "enforce_policy_files",
            "enforce_test_integrity",
            "enforce_secrets",
            "enforce_architecture",
            "enforce_blast_radius",
            "enforce_dependency_provenance",
            "enforce_syntax_integrity",
        }
        assert expected_invariants.issubset(set(invariants.keys()))

    def test_sde_config_never_inherits_financial_domain_keys(self) -> None:
        """Verify load_sde_config never contains financial domain keys."""
        cfg: Dict[str, Any] = load_sde_config()
        forbidden_financial_keys = {
            "financial_domain",
            "trust_model",
            "retrieval_gate",
            "storage",
        }
        for key in forbidden_financial_keys:
            assert key not in cfg, f"SDE config leaked financial domain key: {key}"

    def test_sde_helpers_return_typed_sde_structures(self) -> None:
        """Verify SDE domain accessor helpers return dedicated SDE structures."""
        invariants = get_invariant_config()
        assert isinstance(invariants, dict)
        assert invariants.get("enforce_syntax_integrity") is True

        egress = get_egress_allowlist()
        assert isinstance(egress, list)
        assert "https://github.com/" in egress

        paths = get_protected_paths()
        assert isinstance(paths, list)
        assert "pyproject.toml" in paths

        markers = get_test_markers()
        assert isinstance(markers, list)
        assert "tests/" in markers


class TestFinancialConfigIsolation:
    """Verify Financial configuration loader enforces domain isolation."""

    def test_financial_config_loads_financial_keys(self) -> None:
        """Verify load_config populates financial domain keys."""
        cfg: Dict[str, Any] = load_config()
        assert "financial_domain" in cfg
        assert "trust_model" in cfg
        assert "retrieval_gate" in cfg
        assert "storage" in cfg

        fin = cfg["financial_domain"]
        assert "per_transaction_limit" in fin
        assert "daily_limit" in fin

    def test_financial_config_never_inherits_sde_domain_keys(self) -> None:
        """Verify load_config never contains SDE invariant or guard keys."""
        cfg: Dict[str, Any] = load_config()
        forbidden_sde_keys = {
            "invariants",
            "guard",
            "egress_allowlist",
            "protected_paths",
            "test_markers",
        }
        for key in forbidden_sde_keys:
            assert key not in cfg, f"Financial config leaked SDE domain key: {key}"

    def test_financial_helpers_return_typed_financial_structures(self) -> None:
        """Verify financial domain accessor helpers return dedicated financial structures."""
        trust = get_trust_model_config()
        assert isinstance(trust, dict)
        assert "tau_threshold" in trust

        fin = get_financial_domain_config()
        assert isinstance(fin, dict)
        assert fin.get("per_transaction_limit", 0) > 0


class TestEnvironmentVariableIsolation:
    """Verify mutual environment variable isolation across domains."""

    def test_sde_env_var_does_not_affect_financial_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Setting AGENTPOI_SDE_CONFIG alters SDE config but leaves financial intact."""
        custom_sde = tmp_path / "custom_sde.yaml"
        custom_sde.write_text(
            "guard:\n  policy: permissive\ninvariants:\n  enforce_secrets: false\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("AGENTPOI_SDE_CONFIG", str(custom_sde))

        load_sde_config.cache_clear()
        load_config.cache_clear()

        sde_cfg = load_sde_config()
        assert sde_cfg["guard"]["policy"] == "permissive"
        assert sde_cfg["invariants"]["enforce_secrets"] is False

        fin_cfg = load_config()
        assert "financial_domain" in fin_cfg
        assert "invariants" not in fin_cfg

    def test_financial_env_var_does_not_affect_sde_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Setting AGENT_POI_CONFIG alters financial config but leaves SDE intact."""
        custom_fin = tmp_path / "custom_financial.yaml"
        custom_fin.write_text(
            "financial_domain:\n  per_transaction_limit: 9999.0\ntrust_model:\n  tau_threshold: 0.88\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("AGENT_POI_CONFIG", str(custom_fin))

        load_sde_config.cache_clear()
        load_config.cache_clear()

        fin_cfg = load_config()
        assert fin_cfg["financial_domain"]["per_transaction_limit"] == 9999.0

        sde_cfg = load_sde_config()
        assert "invariants" in sde_cfg
        assert "financial_domain" not in sde_cfg

    def test_cross_pollinated_env_configs_maintain_separation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Simultaneous distinct environment configs remain strictly segregated."""
        sde_file = tmp_path / "env_sde.yaml"
        sde_file.write_text(
            "guard:\n  policy: audit_only\ninvariants:\n  enforce_architecture: false\n",
            encoding="utf-8",
        )
        fin_file = tmp_path / "env_fin.yaml"
        fin_file.write_text(
            "financial_domain:\n  daily_limit: 500000.0\n",
            encoding="utf-8",
        )

        monkeypatch.setenv("AGENTPOI_SDE_CONFIG", str(sde_file))
        monkeypatch.setenv("AGENT_POI_CONFIG", str(fin_file))

        load_sde_config.cache_clear()
        load_config.cache_clear()

        sde_cfg = load_sde_config()
        fin_cfg = load_config()

        assert sde_cfg["guard"]["policy"] == "audit_only"
        assert "financial_domain" not in sde_cfg

        assert fin_cfg["financial_domain"]["daily_limit"] == 500000.0
        assert "invariants" not in fin_cfg


class TestCandidatePathIsolation:
    """Verify candidate path resolvers explicitly avoid cross-domain configuration."""

    def test_sde_resolver_excludes_root_financial_config(self) -> None:
        """Verify SDE path candidate search never targets root config.yaml."""
        from agentpoi_sde.config_loader import _resolve_config_path
        resolved = _resolve_config_path(override_path=None)
        if resolved:
            normalized = resolved.replace("\\", "/")
            assert not normalized.endswith("/config.yaml"), (
                f"SDE config resolved to financial root config.yaml: {resolved}"
            )

    def test_financial_resolver_excludes_sde_config(self) -> None:
        """Verify financial path candidate search never targets sde_config.yaml."""
        from agent_poi.core.config_loader import _resolve_config_path
        resolved = _resolve_config_path(override_path=None)
        if resolved:
            normalized = resolved.replace("\\", "/")
            assert not normalized.endswith("sde_config.yaml"), (
                f"Financial config resolved to SDE config: {resolved}"
            )

    def test_corrupt_files_fall_back_fail_closed_to_defaults(
        self,
        tmp_path: Path,
    ) -> None:
        """Corrupted YAML files safely degrade to domain defaults without cross-bleed."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text(":::invalid: yaml::: syntax error", encoding="utf-8")

        sde_cfg = load_sde_config(str(bad_yaml))
        fin_cfg = load_config(str(bad_yaml))

        assert "invariants" in sde_cfg
        assert "financial_domain" not in sde_cfg

        assert "financial_domain" in fin_cfg
        assert "invariants" not in fin_cfg
