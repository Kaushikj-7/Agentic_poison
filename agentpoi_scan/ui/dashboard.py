"""Interactive Streamlit dashboard for agentpoi-scan (Zone 4).

Zero-execution OSS vulnerability and malicious code auditor.
Enforces strict XSS sanitization and plain-text code display.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import streamlit as st
except ImportError:
    st = None

try:
    import pandas as pd
except ImportError:
    pd = None

from agentpoi_scan.findings.model import CATEGORIES, Finding
from agentpoi_scan.findings.schemas import FindingFilterQuery, ScanTargetRequest
from agentpoi_scan.report.sarif import sarif_document
from agentpoi_scan.report.store import ScanStore
from agentpoi_scan.ui.render import (
    format_autorun_panel,
    format_evidence_trail,
    format_finding_detail,
    format_findings_for_table,
    format_scan_summary,
    is_autorun_finding,
)


def _render_scorecard(summary: Any) -> None:
    """Renders the top two-axis risk scorecard."""
    col1, col2, col3, col4 = st.columns(4)

    vuln = summary.vulnerability_score
    vuln_label = "CRITICAL" if vuln >= 0.8 else ("HIGH" if vuln >= 0.5 else "LOW")
    col1.metric("Vulnerability Risk", f"{vuln:.2f}", f"[{vuln_label}]")

    mal = summary.maliciousness_score
    mal_label = "MALWARE" if mal >= 0.7 else ("SUSPICIOUS" if mal >= 0.4 else "CLEAN")
    col2.metric("Maliciousness Risk", f"{mal:.2f}", f"[{mal_label}]")

    col3.metric(
        "Total Findings",
        str(summary.total_findings),
        f"Crit: {summary.critical_count} | High: {summary.high_count}",
    )

    col4.metric(
        "Autorun Surface",
        str(summary.autorun_count),
        f"Isolation: {summary.isolation_level}",
    )


def _render_findings_matrix(findings: List[Finding]) -> None:
    """Renders Tab 1: Findings Matrix and expanded detail."""
    if not findings:
        st.info("No findings match the selected criteria.")
        return

    table_data = format_findings_for_table(findings)
    if pd is not None:
        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True)
    else:
        st.table(table_data)

    st.markdown("---")
    st.subheader("Finding Inspection & Evidence Trail")

    options = [
        f"[{f.severity.upper()}] {f.title} ({f.file}:{min(f.lines) if f.lines else 0})"
        for f in findings
    ]
    selected_idx = st.selectbox(
        "Select finding to inspect",
        range(len(findings)),
        format_func=lambda i: options[i],
    )
    finding = findings[selected_idx]

    detail_vm = format_finding_detail(finding, raw_snippet=finding.detail)

    c1, c2, c3, c4 = st.columns(4)
    c1.text(f"Scanner: {detail_vm.scanner}")
    c2.text(f"Status: {detail_vm.status}")
    c3.text(f"Confidence: {detail_vm.confidence:.2f}")
    c4.text(f"Fingerprint: {detail_vm.fingerprint[:16]}...")

    st.markdown("**Evidence Trail:**")
    evidence = format_evidence_trail(finding)
    if evidence:
        for idx, ev in enumerate(evidence, start=1):
            source = ev.get("source", "unknown")
            st.text(f"  Step {idx} [{source}]: {json.dumps(ev)}")
    else:
        st.text("  No intermediate LLM evidence items recorded.")

    if detail_vm.model_trail:
        st.text(f"Model Trail: {' -> '.join(detail_vm.model_trail)}")

    st.markdown("**Quarantined Code / Payload (Escaped):**")
    # Strictly safe: st.code renders text safely without HTML/script execution
    st.code(detail_vm.escaped_snippet or "No snippet captured.", language="text")


def _render_autorun_surface(findings: List[Finding]) -> None:
    """Renders Tab 2: Autorun Surface findings."""
    autorun_rows = format_autorun_panel(findings)
    if not autorun_rows:
        st.success("No suspicious autorun surface entries detected.")
        return

    st.warning(f"Detected {len(autorun_rows)} findings on the repository autorun/install surface.")
    if pd is not None:
        st.dataframe(pd.DataFrame(autorun_rows), use_container_width=True)
    else:
        st.table(autorun_rows)


def _render_category_distribution(findings: List[Finding]) -> None:
    """Renders Tab 3: Heatmap / Category breakdown."""
    cat_counts: Dict[str, int] = {cat: 0 for cat in CATEGORIES}
    for f in findings:
        if f.category in cat_counts:
            cat_counts[f.category] += 1

    active_cats = {k: v for k, v in cat_counts.items() if v > 0}
    if not active_cats:
        st.info("No findings to display in category breakdown.")
        return

    if pd is not None:
        chart_df = pd.DataFrame(
            list(active_cats.items()), columns=["Category", "Findings Count"]
        ).set_index("Category")
        st.bar_chart(chart_df)
    else:
        for cat, cnt in active_cats.items():
            st.text(f"{cat}: {cnt}")


def _render_sarif_export(scan_id: int, findings: List[Finding]) -> None:
    """Renders Tab 4: SARIF 2.1 Export."""
    st.subheader("SARIF 2.1 Export")
    doc = sarif_document(findings)
    sarif_json = json.dumps(doc, indent=2)

    st.download_button(
        label="Download SARIF 2.1 JSON",
        data=sarif_json,
        file_name=f"scan_{scan_id}.sarif",
        mime="application/json",
    )
    st.code(sarif_json[:1000] + "\n...", language="json")


def main_app(store_path: Optional[str | Path] = None) -> None:
    """Main Streamlit dashboard entry point."""
    if st is None:
        raise RuntimeError("Streamlit is required to run the dashboard. Install agent-poi[scan-ui].")

    st.set_page_config(
        page_title="agentpoi-scan: Zero-Execution OSS Auditor",
        layout="wide",
    )

    store_file = Path(store_path or ".agentpoi_scan/scan_store.sqlite3")
    store = ScanStore(store_file)

    try:
        st.title("AGENTPOI-SCAN: ZERO-EXECUTION OSS VULNERABILITY & MALICIOUS CODE AUDITOR")
        st.caption("Isolation Boundary: In-Process (Weak) | Deterministic Zone 2 + Non-Frontier Zone 3")

        # Scan Trigger Section
        with st.expander("Target Repository Scanner", expanded=False):
            c1, c2, c3 = st.columns([3, 2, 1])
            repo_url = c1.text_input("Repository (URL or owner/repo)", "https://github.com/victim/target-repo")
            ref = c2.text_input("Branch / Commit SHA (optional)", "")
            trigger_scan = c3.button("Run Scan", type="primary")

            if trigger_scan and repo_url:
                import yaml

                from agentpoi_scan.pipeline import ScanPipeline

                try:
                    target_req = ScanTargetRequest(
                        repo_url=repo_url.strip(),
                        ref=ref.strip() or None,
                    )
                except Exception as val_err:  # noqa: BLE001
                    st.error(f"Invalid target parameters: {val_err}")
                    target_req = None

                if target_req:
                    cfg_path = Path(__file__).resolve().parents[1] / "config" / "scanner_config.yaml"
                    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) if cfg_path.is_file() else {}
                    pipeline = ScanPipeline(config=cfg, store_path=store_file)
                    with st.spinner("Executing Zero-Execution Static Scan..."):
                        try:
                            pipeline.scan_target(target_req.repo_url, ref=target_req.ref)
                            st.success("Scan completed successfully!")
                        except Exception as exc:  # noqa: BLE001
                            st.error(f"Scan failed: {exc}")
                        finally:
                            pipeline.store.close()

        scans = store.list_scans(limit=50)
        if not scans:
            st.info("No scans recorded in the store yet. Run a scan above to view results.")
            return

        scan_options = {
            f"Scan #{s['id']}: {s['repo']} @ {s['commit_sha'][:8]} ({s['created_at'][:19]})": s["id"]
            for s in scans
        }
        selected_label = st.selectbox("Select Historic Scan", list(scan_options.keys()))
        scan_id = scan_options[selected_label]

        scan_meta = store.get_scan(scan_id)
        if not scan_meta:
            st.error(f"Scan #{scan_id} not found in store.")
            return

        severity_counts = store.count_findings_by_severity(scan_id)
        all_scan_findings = store.get_findings_filtered(scan_id)
        autorun_count = len([f for f in all_scan_findings if is_autorun_finding(f)])

        summary = format_scan_summary(scan_meta, severity_counts, autorun_count=autorun_count)
        _render_scorecard(summary)

        # Filter Controls
        fc1, fc2, fc3, fc4 = st.columns(4)
        sel_sev = fc1.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
        sel_cat = fc2.selectbox("Category", ["All", *CATEGORIES])
        sel_status = fc3.selectbox(
            "Status",
            ["All", "open", "triaged", "confirmed", "refuted", "escalated", "human_review"],
        )
        sel_search = fc4.text_input("Search (title, file, detail)", "").strip()

        try:
            filter_query = FindingFilterQuery(
                scan_id=scan_id,
                severity=None if sel_sev == "All" else sel_sev,  # type: ignore
                category=None if sel_cat == "All" else sel_cat,  # type: ignore
                status=None if sel_status == "All" else sel_status,  # type: ignore
                search_query=sel_search or None,
            )
        except Exception as exc:  # noqa: BLE001
            st.warning(f"Filter validation: {exc}")
            filter_query = FindingFilterQuery(scan_id=scan_id)

        filtered_findings = store.get_findings_filtered(
            scan_id=filter_query.scan_id,
            severity=filter_query.severity,
            category=filter_query.category,
            status=filter_query.status,
            search=filter_query.search_query,
        )

        t1, t2, t3, t4 = st.tabs(
            ["Findings Matrix", "Autorun Surface", "Category Breakdown", "SARIF Export"]
        )
        with t1:
            _render_findings_matrix(filtered_findings)
        with t2:
            _render_autorun_surface(all_scan_findings)
        with t3:
            _render_category_distribution(all_scan_findings)
        with t4:
            _render_sarif_export(scan_id, all_scan_findings)
    finally:
        store.close()


def run_dashboard(store_path: Optional[str | Path] = None, port: int = 8501) -> None:
    """Programmatic launcher for the Streamlit dashboard."""
    if st is None:
        raise RuntimeError("Streamlit is required to run the dashboard. Install agent-poi[scan-ui].")
    import subprocess
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(Path(__file__).resolve()),
        "--server.port",
        str(port),
    ]
    if store_path:
        cmd.extend(["--", "--store-path", str(store_path)])
    subprocess.run(cmd, check=False)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--store-path", default=".agentpoi_scan/scan_store.sqlite3")
    parsed, _ = parser.parse_known_args()
    main_app(store_path=parsed.store_path)
