"""``agentpoi-scan`` CLI — scan a GitHub repo without ever executing it."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml


def _load_config(path: str | Path) -> dict:
    path = Path(path)
    if not path.is_file():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return payload if isinstance(payload, dict) else {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentpoi-scan",
        description="Static-only vulnerability and malicious-code scanner for GitHub repositories. "
        "Never installs, builds or runs scanned code.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", aliases=["run"], help="scan one GitHub repository or local directory")
    p_scan.add_argument("repo", help="GitHub URL, owner/name, or local directory path")
    p_scan.add_argument("--branch", default=None, help="branch/SHA to pin (defaults to repo HEAD)")
    p_scan.add_argument("--config", default=None, help="path to scanner_config.yaml")
    p_scan.add_argument("--sarif", "--output-sarif", dest="sarif", default=None, help="override the SARIF output path")
    p_scan.add_argument("--offline", "--no-llm", dest="offline", action="store_true", help="run 100%% offline CPU without advisory LLM triage")
    p_scan.add_argument("--workdir", default=None, help="working directory for snapshots/store")

    p_validate = sub.add_parser("validate", help="validate a scan_registry directory")
    p_validate.add_argument("registry", help="path to scan_registry/<name>/ directories")

    p_dashboard = sub.add_parser("dashboard", help="launch interactive Streamlit dashboard")
    p_dashboard.add_argument("--port", type=int, default=8501, help="port to bind the dashboard")
    p_dashboard.add_argument(
        "--store-path",
        default=".agentpoi_scan/scan_store.sqlite3",
        help="path to SQLite scan store",
    )

    args = parser.parse_args(argv)

    if args.command == "dashboard":
        try:
            import streamlit  # noqa: F401
        except (ImportError, ModuleNotFoundError):
            print(
                "ERROR: Streamlit is not installed. Install with 'pip install agent-poi[scan-ui]' to run the dashboard."
            )
            return 1

        from agentpoi_scan.ui.dashboard import run_dashboard, st

        if st is None:
            print(
                "ERROR: Streamlit is not installed. Install with 'pip install agent-poi[scan-ui]' to run the dashboard."
            )
            return 1

        run_dashboard(store_path=args.store_path, port=args.port)
        return 0

    if args.command == "validate":
        from agentpoi_scan.pipeline import validate_targets

        errors = validate_targets(args.registry)
        if errors:
            print("REGISTRY: FAIL")
            for error in errors:
                print(f"  - {error}")
            return 2
        print("REGISTRY: OK")
        return 0

    if args.command in ("scan", "run"):
        from agentpoi_scan.pipeline import ScanPipeline

        cfg = _load_config(args.config or Path(__file__).parent / "config" / "scanner_config.yaml")
        if getattr(args, "offline", False):
            if not isinstance(cfg.get("privacy"), dict):
                cfg["privacy"] = {}
            cfg["privacy"]["local_only"] = True
        if args.sarif:
            cfg["sarif_path"] = args.sarif
        token = os.environ.get("GITHUB_TOKEN") or cfg.get("github_token")
        if token:
            cfg["github_token"] = token
        pipeline = ScanPipeline(config=cfg, store_path=Path(args.workdir or ".agentpoi_scan") / "scan_store.sqlite3")
        try:
            report = pipeline.scan_target(args.repo, ref=args.branch, workdir=Path(args.workdir or ".agentpoi_scan"))
        except Exception as exc:  # noqa: BLE001 — CLI boundary: report and fail closed
            print(f"SCAN: FAIL ({exc})")
            return 1
        print("SCAN: COMPLETE")
        print(report.summary())
        print(f"sarif: {pipeline.sarif_path}")
        print(f"dashboard report: scan #{report.scan_id} in {pipeline.store.path}")
        return 0

    sys.exit(1)  # pragma: no cover — argparse enforces subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
