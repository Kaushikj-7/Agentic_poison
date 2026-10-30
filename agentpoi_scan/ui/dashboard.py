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

from agentpoi_scan.findings.model import CATEGORIES, Finding, severity_rank
from agentpoi_scan.findings.schemas import FindingFilterQuery, ScanTargetRequest
from agentpoi_scan.report.sarif import sarif_document
from agentpoi_scan.report.store import ScanStore
from agentpoi_scan.ui.render import (
    format_autorun_panel,
    format_evidence_trail,
    format_file_remediation,
    format_finding_detail,
    format_findings_for_table,
    format_flagged_files,
    format_scan_summary,
    format_severity_badge,
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
    _render_finding_detail(finding)


def _render_finding_detail(finding: Finding) -> None:
    """Renders one finding's location, evidence trail and vulnerable source."""
    detail_vm = format_finding_detail(finding)
    st.text(f"Source: {detail_vm.location}")

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

    st.markdown("**Vulnerable Source at Reported Location (Escaped):**")
    # Strictly safe: st.code renders text safely without HTML/script execution
    st.code(detail_vm.escaped_snippet or "No snippet captured.", language="text")


def _render_flagged_files(findings: List[Finding]) -> None:
    """Renders the per-file flag table and a drill-down for one flagged file."""
    rows = format_flagged_files(findings)
    if not rows:
        st.info("No files are flagged for this scan.")
        return

    st.subheader("Flagged Files")
    st.caption(
        f"{len(rows)} file(s) carry at least one finding. Worst severity first; "
        "select a file to see exactly what was flagged inside it."
    )
    if pd is not None:
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.table(rows)

    st.markdown("---")
    st.subheader("Flagged File Inspector")
    badge_by_file = {row["file"]: row["badge"] for row in rows}
    selected_file = st.selectbox(
        "Select a flagged file",
        [row["file"] for row in rows],
        format_func=lambda path: f"{badge_by_file.get(path, '')}  {path}",
    )
    selected_row = next(row for row in rows if row["file"] == selected_file)
    file_findings = [f for f in findings if f.file == selected_file]
    file_findings.sort(
        key=lambda f: (-severity_rank(f.severity), min(f.lines) if f.lines else 0)
    )
    st.text(
        f"File: {selected_file}  |  severity: {selected_row['badge']}  |  "
        f"role: {selected_row['role']}  |  findings: {len(file_findings)}"
    )

    st.markdown("**Remediation for this file**")
    notes = format_file_remediation(file_findings)
    if notes:
        for note in notes:
            st.markdown(f"- {note}")
    else:
        st.text("No automated remediation guidance available for this file.")

    if pd is not None:
        st.dataframe(
            pd.DataFrame(format_findings_for_table(file_findings)), use_container_width=True
        )
    else:
        st.table(format_findings_for_table(file_findings))

    options = [
        f"{format_severity_badge(f.severity)} {f.location} — {f.title}" for f in file_findings
    ]
    selected_idx = st.selectbox(
        "Select finding inside this file",
        range(len(file_findings)),
        format_func=lambda i: options[i],
    )
    _render_finding_detail(file_findings[selected_idx])


def _render_codebase_report(report: Optional[Dict[str, Any]]) -> None:
    """Renders the stored examination report: isolation, codebase, coverage."""
    if not report:
        st.info(
            "No stored report for this scan. Reports are written by scans run with "
            "the current pipeline; re-run the scan to generate one."
        )
        return

    st.subheader("Examination Report")
    isolation = report.get("isolation") or {}
    st.text("Isolation & cleanup")
    for key in ("mode", "network", "workspace", "purged", "removed_files", "removed_bytes"):
        if key in isolation:
            st.text(f"  {key}: {isolation[key]}")
    if isolation.get("purged") == "true":
        st.success("Ephemeral workspace deleted after examination; only the report persists.")
    elif isolation.get("purged") == "false":
        st.error("Workspace purge failed — source may remain on disk.")

    codebase = report.get("codebase") or {}
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Files examined", str(codebase.get("total_files", 0)))
    c2.metric("Dependencies", str(codebase.get("dependency_count", 0)))
    c3.metric("HTTP routes", str(codebase.get("route_count", 0)))
    c4.metric("Entrypoints", str(len(codebase.get("entrypoints") or [])))

    st.markdown("**Languages**")
    languages = codebase.get("languages") or {}
    if languages:
        if pd is not None:
            st.bar_chart(pd.DataFrame(list(languages.items()), columns=["Language", "Files"]).set_index("Language"))
        else:
            for language, count in languages.items():
                st.text(f"  {language}: {count}")
    else:
        st.text("  No recognized source languages.")

    st.markdown("**Dependencies**")
    dependencies = codebase.get("dependencies") or []
    if dependencies:
        rows = [
            {
                "name": dep.get("name", ""),
                "specifier": dep.get("specifier", ""),
                "ecosystem": dep.get("ecosystem", ""),
                "source": dep.get("source", ""),
                "pinned": bool(dep.get("pinned")),
                "manifest": dep.get("manifest", ""),
                "line": dep.get("line", 0),
            }
            for dep in dependencies[:500]
        ]
        if pd is not None:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.table(rows)
    else:
        st.text("  No supported dependency manifest detected.")

    st.markdown("**HTTP routes (statically extracted)**")
    routes = codebase.get("routes") or []
    if routes:
        if pd is not None:
            st.dataframe(pd.DataFrame(routes), use_container_width=True)
        else:
            st.table(routes)
    else:
        st.text("  No route declarations detected.")

    st.markdown("**Entrypoints & scripts**")
    entrypoints = codebase.get("entrypoints") or []
    if entrypoints:
        if pd is not None:
            st.dataframe(pd.DataFrame(entrypoints), use_container_width=True)
        else:
            st.table(entrypoints)
    scripts = codebase.get("scripts") or {}
    for manifest, names in scripts.items():
        st.text(f"  {manifest}: {', '.join(names)}")

    skipped = report.get("skipped_scanners") or {}
    if skipped:
        st.markdown("**Scanners that did not run**")
        for name, reason in sorted(skipped.items()):
            st.text(f"  {name}: {reason}")

    st.download_button(
        label="Download examination report (JSON)",
        data=json.dumps(report, indent=2),
        file_name=f"scan_{report.get('scan_id', 'report')}_report.json",
        mime="application/json",
    )


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
        st.caption("Enter any public GitHub repository or owner/repo. Scans are static and never execute repository code.")

        # Scan Trigger Section
        with st.expander("Target Repository Scanner", expanded=False):
            c1, c2, c3 = st.columns([3, 2, 1])
            repo_url = c1.text_input("Any public GitHub repository (URL or owner/repo)", "")
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
                            report = pipeline.scan_target(
                                target_req.repo_url,
                                ref=target_req.ref,
                                workdir=store_file.parent,
                            )
                            st.success("Scan completed successfully!")
                            isolation = report.isolation or {}
                            if isolation.get("purged") == "true":
                                st.success(
                                    "Ephemeral workspace deleted after examination "
                                    f"({isolation.get('removed_files', 0)} files, "
                                    f"{isolation.get('removed_bytes', 0)} bytes)."
                                )
                            if report.skipped_scanners:
                                skipped = ", ".join(
                                    f"{name}: {reason}"
                                    for name, reason in sorted(report.skipped_scanners.items())
                                )
                                st.warning(f"Optional scanners did not run: {skipped}")
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
        report = store.get_report(scan_id)
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

        t1, t2, t3, t4, t5, t6 = st.tabs(
            [
                "Flagged Files",
                "Examination Report",
                "Findings Matrix",
                "Autorun Surface",
                "Category Breakdown",
                "SARIF Export",
            ]
        )
        with t1:
            _render_flagged_files(all_scan_findings)
        with t2:
            _render_codebase_report(report)
        with t3:
            _render_findings_matrix(filtered_findings)
        with t4:
            _render_autorun_surface(all_scan_findings)
        with t5:
            _render_category_distribution(all_scan_findings)
        with t6:
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
