"""Tests for env-based key/model resolution and free-tier rate limits (llm_bridge)."""

import os

import pytest

from agentpoi_scan.agents.llm_bridge import (
    RateLimitedProvider,
    TieredProviders,
    _load_env_file,
    build_default_providers,
)


def _chain_cfg(model: str = "") -> dict:
    return {
        "tiers": {
            "local": {"provider": "ollama"},
            "verifier": {"provider": "ollama"},
            "frontier": {"provider": "openrouter", "model": model},
        },
        "limits": {"requests_per_minute": 15, "max_requests_per_scan": 40},
    }


class CountingProvider:
    def __init__(self, content='{"ok": true}'):
        self.calls = 0
        self.content = content

    def generate(self, prompt, system_prompt=None):
        self.calls += 1
        return {"content": self.content}


# -- .env autoloader (stdlib fallback) -------------------------------------------
def test_load_env_file_sets_missing_keys_only(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nOPENROUTER_MODEL=repo/model:free\nQUOTED_KEY = 'v1-abc'\n\nBADLINE\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    monkeypatch.delenv("QUOTED_KEY", raising=False)
    monkeypatch.setenv("PRESET_KEY", "live-wins")
    env_file.write_text(env_file.read_text(encoding="utf-8") + "PRESET_KEY=from-file\n", encoding="utf-8")

    _load_env_file(str(env_file))

    assert os.environ["OPENROUTER_MODEL"] == "repo/model:free"
    assert os.environ["QUOTED_KEY"] == "v1-abc"
    assert os.environ["PRESET_KEY"] == "live-wins", "existing env must never be overridden"


def test_load_env_file_missing_or_undreadable_is_noop(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    _load_env_file(str(tmp_path / "does_not_exist.env"))
    assert os.environ.get("OPENROUTER_MODEL") is None


# -- frontier model resolution ------------------------------------------------
def test_frontier_model_resolves_from_env_when_config_blank(monkeypatch):
    monkeypatch.setenv("OPENROUTER_MODEL", "test/free-model:free")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test")
    providers, unavailable = build_default_providers(_chain_cfg(model=""))
    assert "frontier" in providers.providers
    assert "frontier" not in unavailable
    wrapped = providers.providers["frontier"]
    assert isinstance(wrapped, RateLimitedProvider)
    assert wrapped.provider.model == "test/free-model:free"


def test_config_model_beats_env(monkeypatch):
    monkeypatch.setenv("OPENROUTER_MODEL", "env/model:free")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test")
    providers, _ = build_default_providers(_chain_cfg(model="config/model:free"))
    assert providers.providers["frontier"].provider.model == "config/model:free"


def test_missing_key_fails_closed(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    providers, unavailable = build_default_providers(_chain_cfg())
    assert "frontier" not in providers.providers
    assert unavailable["frontier"] == "OPENROUTER_API_KEY not set"


def test_limits_applied_to_frontier(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test")
    cfg = _chain_cfg()
    cfg["limits"] = {"requests_per_minute": 5, "max_requests_per_scan": 7, "max_backoff_seconds": 1}
    providers, _ = build_default_providers(cfg)
    wrapped = providers.providers["frontier"]
    assert wrapped.requests_per_minute == 5
    assert wrapped.max_requests_per_scan == 7
    assert wrapped.max_backoff_seconds == 1.0


# -- free-tier caps, fail-closed ------------------------------------------------
def test_per_scan_cap_makes_tier_unavailable():
    inner = CountingProvider()
    limiter = RateLimitedProvider(inner, requests_per_minute=1000, max_requests_per_scan=2)
    bridge = TieredProviders({"frontier": limiter}, tiers=("frontier",))
    assert bridge.complete_json("frontier", "p1", "s", ("ok",)) == {"ok": True}
    assert bridge.complete_json("frontier", "p2", "s", ("ok",)) == {"ok": True}
    assert inner.calls == 2
    assert limiter.is_available() is False
    # cap exhausted → further calls never reach the provider
    assert bridge.complete_json("frontier", "p3", "s", ("ok",)) is None
    assert inner.calls == 2


def test_rpm_window_throttles_then_dispatches():
    inner = CountingProvider()
    t = [100.0]
    sleeps = []
    limiter = RateLimitedProvider(
        inner,
        requests_per_minute=1,
        max_requests_per_scan=10,
        max_backoff_seconds=59.0,
        _sleep=lambda s: sleeps.append(s),
        _now=lambda: t[0],
    )

    limiter.generate("p1")  # first request: window fresh
    assert sleeps == [] and inner.calls == 1

    t[0] = 101.0  # second request 1s later: same minute → sleep 59s, then send
    limiter.generate("p2")
    assert sleeps == [59.0] and inner.calls == 2
    # the delayed request opened the new window — it must not leak into the old count
    assert limiter._window_start == 101.0 and limiter._window_count == 1


def test_rpm_third_call_two_minutes_apart_never_sleeps():
    inner = CountingProvider()
    t = [100.0]
    sleeps = []
    limiter = RateLimitedProvider(
        inner,
        requests_per_minute=1,
        max_requests_per_scan=10,
        max_backoff_seconds=59.0,
        _sleep=lambda s: sleeps.append(s),
        _now=lambda: t[0],
    )
    limiter.generate("p1")
    t[0] = 101.0  # throttle → sleep 59s; window rebased to 101
    limiter.generate("p2")
    t[0] = 102.0  # 1s after the rebased window opened → must sleep again, not send free
    limiter.generate("p3")
    assert sleeps == [59.0, 59.0], "rebased window must re-throttle the next request"
    assert inner.calls == 3


def test_delegates_inner_availability_and_fails_closed():
    inner = CountingProvider()
    inner.is_available = lambda: False  # e.g. wrong-shaped API key
    limiter = RateLimitedProvider(inner, requests_per_minute=1000, max_requests_per_scan=10)
    bridge = TieredProviders({"frontier": limiter}, tiers=("frontier",))
    assert limiter.is_available() is False
    assert bridge.complete_json("frontier", "p", "s", ("ok",)) is None
    assert inner.calls == 0, "unavailable inner provider must never receive requests"


def test_delegation_tolerates_doubles_without_is_available():
    inner = CountingProvider()  # no is_available attribute → counts as available
    limiter = RateLimitedProvider(inner, requests_per_minute=1000, max_requests_per_scan=10)
    assert limiter.is_available() is True


def test_rpm_degrades_past_backoff_budget_instead_of_sending():
    inner = CountingProvider()
    sleeps = []
    t = [100.0]
    limiter = RateLimitedProvider(
        inner,
        requests_per_minute=1,
        max_requests_per_scan=10,
        max_backoff_seconds=1.0,
        _sleep=lambda s: sleeps.append(s),
        _now=lambda: t[0],
    )
    limiter.generate("p1")
    t[0] = 101.0  # 59s remaining in window, backoff budget only 1s → refuse
    with pytest.raises(RuntimeError):
        limiter.generate("p2")
    assert inner.calls == 1 and sleeps == []


def test_minute_window_reset_allows_new_burst():
    inner = CountingProvider()
    t = [100.0]
    limiter = RateLimitedProvider(
        inner,
        requests_per_minute=1,
        max_requests_per_scan=10,
        max_backoff_seconds=59.0,
        _sleep=lambda s: None,
        _now=lambda: t[0],
    )
    limiter.generate("p1")
    t[0] = 161.0  # window rolled over
    limiter.generate("p2")
    assert inner.calls == 2
