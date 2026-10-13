"""Public CLI interface for AgentPOI-SDE.

Exposes subcommands for:
- Repository state anchor R0 computation and inspection (`anchor`)
- Fail-closed unified diff and git mutation validation (`check-diff`)
- Dynamic adaptive benchmark audits with structured reporting (`benchmark`)
"""

import argparse
import json
import os
import re
import sys
from typing import List, Optional, Tuple

__version__ = "0.1.0"
from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor
from agentpoi_sde.delta.diff_parser import (
    MalformedDiffError,
    extract_git_mutations,
    parse_unified_diff,
)
from agentpoi_sde.domain import CodeMutation, GuardPolicy
from agentpoi_sde.eval.benchmark import run_benchmark
from agentpoi_sde.facade import DevGuard


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="agentpoi-sde",
        description="AgentPOI-SDE: Fail-Closed Repository Invariant Verification CLI",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"agentpoi-sde {__version__}",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. anchor
    p_anchor = subparsers.add_parser(
        "anchor",
        help="Inspect and compute R0 state anchor for a repository or directory",
    )
    p_anchor.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to repository or target directory (default: current directory)",
    )
    p_anchor.add_argument(
        "--json",
        action="store_true",
        help="Output anchor metadata as JSON",
    )
    p_anchor.add_argument(
        "--manifest",
        action="store_true",
        help="Include full file content-hash manifest in output",
    )

    # 2. check-diff
    p_diff = subparsers.add_parser(
        "check-diff",
        help="Validate git diff or patch fail-closed against repository invariants",
    )
    p_diff.add_argument(
        "patch_file",
        nargs="?",
        default=None,
        help="Path to diff/patch file, or '-' for standard input",
    )
    p_diff.add_argument(
        "--repo",
        default=".",
        help="Path to root of repository or target directory (default: .)",
    )
    p_diff.add_argument(
        "--staged",
        action="store_true",
        help="Inspect staged changes in git repository instead of unstaged",
    )
    p_diff.add_argument(
        "--allow",
        action="append",
        default=[],
        help="Path or glob pattern permitted by intent contract (may be repeated)",
    )
    p_diff.add_argument(
        "--intent-id",
        default="INTENT-CLI-DIFF",
        help="Intent identifier for verification contract",
    )
    p_diff.add_argument(
        "--json",
        action="store_true",
        help="Output verification verdict and violations as JSON",
    )

    # 3. benchmark
    p_bench = subparsers.add_parser(
        "benchmark",
        help="Run dynamic adaptive benchmark audits against defense sandbox",
    )
    p_bench.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Random seed for benchmark scenario generation (default: 0)",
    )
    p_bench.add_argument(
        "--per-family",
        type=int,
        default=2,
        help="Number of adversarial scenarios per attack family (default: 2)",
    )
    p_bench.add_argument(
        "--clean-per-family",
        type=int,
        default=2,
        help="Number of clean control scenarios per family (default: 2)",
    )
    p_bench.add_argument(
        "--format",
        choices=["markdown", "json", "both"],
        default="markdown",
        help="Output format (markdown, json, both; default: markdown)",
    )
    p_bench.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional destination file path for benchmark report",
    )

    return parser


def handle_anchor(args: argparse.Namespace) -> int:
    """Handle the 'anchor' subcommand."""
    target_path = os.path.abspath(args.path)
    if not os.path.isdir(target_path):
        sys.stderr.write(f"Error: Target directory does not exist: {target_path}\n")
        return 2

    anchor = RepositoryStateAnchor.from_directory(target_path)
    tree_oid = anchor.tree_oid()
    files_count = len(anchor.files)
    verified_deps = sorted(anchor.verified_dependencies())
    ext_deps = sorted(anchor.external_dependencies())
    cycles = anchor.cycles()

    if args.json:
        payload = {
            "root_dir": target_path.replace("\\", "/"),
            "tree_oid": tree_oid,
            "files_count": files_count,
            "verified_dependencies": verified_deps,
            "external_dependencies": ext_deps,
            "cycles": cycles,
        }
        if args.manifest:
            payload["manifest"] = {
                p: anchor.file_hash(p) for p in sorted(anchor.files)
            }
        print(json.dumps(payload, indent=2))
        return 0

    print("==================================================")
    print("AgentPOI-SDE: Repository State Anchor (R0)")
    print("==================================================")
    print(f"Directory:             {target_path}")
    print(f"Root Tree OID:         {tree_oid}")
    print(f"Indexed Files:         {files_count}")
    print(f"Verified Dependencies: {len(verified_deps)} ({', '.join(verified_deps[:5])}{'...' if len(verified_deps) > 5 else ''})")
    print(f"External Dependencies: {len(ext_deps)}")
    print(f"Dependency Cycles:     {len(cycles)}")

    if args.manifest:
        print("\n--- File Manifest ---")
        for p in sorted(anchor.files):
            print(f"{anchor.file_hash(p)[:12]}  {p}")

    return 0


def _load_diff_text(patch_file: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """Read diff text from patch file or stdin. Returns (text, error_code)."""
    if patch_file == "-":
        return sys.stdin.read(), None
    if patch_file:
        if not os.path.isfile(patch_file):
            sys.stderr.write(f"Error: Patch file does not exist: {patch_file}\n")
            return None, 2
        try:
            with open(patch_file, "r", encoding="utf-8", errors="replace") as f:
                return f.read(), None
        except Exception as exc:
            sys.stderr.write(f"Error reading patch file: {exc}\n")
            return None, 2
    return None, None


def _collect_mutations(
    args: argparse.Namespace, anchor: RepositoryStateAnchor
) -> Tuple[Optional[List[CodeMutation]], Optional[int]]:
    """Gather mutations from patch file or git working tree."""
    diff_text, err = _load_diff_text(args.patch_file)
    if err is not None:
        return None, err

    if diff_text is not None:
        try:
            mutations = parse_unified_diff(diff_text, base_files=anchor.to_files())
            return mutations, None
        except (MalformedDiffError, ValueError, SyntaxError) as exc:
            sys.stderr.write(f"Error: Malformed or unparsable diff: {exc}\n")
            return None, 2

    repo_dir = os.path.abspath(args.repo)
    try:
        mutations = extract_git_mutations(repo_path=repo_dir, staged=args.staged)
        return mutations, None
    except Exception as exc:
        sys.stderr.write(f"Error extracting git mutations: {exc}\n")
        return None, 2


def _validate_mutation_path(path: str, repo_dir: Optional[str] = None) -> Optional[str]:
    """Validate path for directory traversal, absolute paths, and internal directories.

    Returns an error message if disallowed, or None if valid.
    """
    norm = path.replace("\\", "/").strip()
    if norm.startswith("/") or re.match(r"^[a-zA-Z]:", norm):
        return f"Absolute path mutation rejected: {path}"
    parts = [p for p in norm.split("/") if p and p != "."]
    if ".." in parts:
        return f"Directory traversal escape rejected: {path}"
    if any(p in (".git", ".agents") for p in parts):
        return f"Tampering with internal governance directory rejected: {path}"
    if repo_dir:
        abs_repo = os.path.abspath(repo_dir)
        target = os.path.abspath(os.path.join(abs_repo, norm))
        try:
            if os.path.commonpath([abs_repo, target]) != abs_repo:
                return f"Path escapes repository root directory: {path}"
        except ValueError:
            return f"Path escapes repository root directory (cross-drive): {path}"
    return None


def handle_check_diff(args: argparse.Namespace) -> int:
    """Handle the 'check-diff' subcommand."""
    repo_dir = os.path.abspath(args.repo)
    if not os.path.isdir(repo_dir):
        sys.stderr.write(f"Error: Repository directory does not exist: {repo_dir}\n")
        return 2

    anchor = RepositoryStateAnchor.from_directory(repo_dir)
    mutations, err = _collect_mutations(args, anchor)
    if err is not None:
        return err

    if not mutations:
        if args.json:
            print(json.dumps({"verdict": "APPROVED", "mutations": [], "violations": []}, indent=2))
        else:
            print("VERDICT: APPROVED (0 mutations)")
        return 0

    all_approved = True
    all_violations: List[str] = []
    mutation_reports: List[dict] = []
    valid_mutations: List[CodeMutation] = []

    for mutation in mutations:
        err_msg = _validate_mutation_path(mutation.path, repo_dir=repo_dir)
        if err_msg:
            all_approved = False
            v_code = "I1"
            formatted = f"[{v_code}] {err_msg}"
            all_violations.append(formatted)
            mutation_reports.append({
                "path": mutation.path,
                "op": mutation.op.value,
                "status": "BLOCKED",
                "violations": [err_msg],
                "violation_codes": [v_code],
            })
        else:
            valid_mutations.append(mutation)

    if valid_mutations:
        guard = DevGuard(
            policy=GuardPolicy.STRICT,
            files=anchor.to_files(),
            architecture_policy=anchor.policy,
            dependency_allowlist=anchor.declared_dependencies,
            design_decisions=anchor.design_decisions,
        )

        allowed = list(args.allow) if args.allow else [
            m.path for m in valid_mutations if not anchor.is_protected(m.path)
        ]
        if not allowed:
            allowed = ["__none__"]

        intent = guard.register_intent(
            intent_id=args.intent_id,
            goal="CLI check-diff verification",
            allowed_paths=allowed,
        )

        for mutation in valid_mutations:
            nonce = f"cli-{mutation.path}-{mutation.op.value}"
            verdict = guard.propose_mutation(mutation, intent.intent_id, nonce=nonce)
            if not verdict.is_applied:
                all_approved = False
            for code, msg in zip(verdict.violation_codes, verdict.violations):
                formatted = f"[{code}] {msg}" if not msg.startswith(f"[{code}]") else msg
                all_violations.append(formatted)
            mutation_reports.append({
                "path": mutation.path,
                "op": mutation.op.value,
                "status": verdict.status,
                "violations": verdict.violations,
                "violation_codes": verdict.violation_codes,
            })

    overall_status = "APPROVED" if all_approved else "BLOCKED"
    if args.json:
        print(json.dumps({
            "verdict": overall_status,
            "mutations": mutation_reports,
            "violations": all_violations,
        }, indent=2))
    else:
        print("==================================================")
        print(f"VERDICT: {overall_status} ({len(all_violations)} invariant violation(s) across {len(mutations)} mutation(s))")
        print("==================================================")
        if all_violations:
            print("\nViolations:")
            for v in all_violations:
                print(f"  - {v}")

    return 0 if all_approved else 1


def handle_benchmark(args: argparse.Namespace) -> int:
    """Handle the 'benchmark' subcommand."""
    report = run_benchmark(
        seed=args.seed,
        per_family=args.per_family,
        clean_per_family=args.clean_per_family,
    )

    if args.format == "markdown":
        output_text = report.to_markdown()
    elif args.format == "json":
        output_text = report.to_json(indent=2)
    else:
        output_text = f"{report.to_markdown()}\n\n```json\n{report.to_json(indent=2)}\n```"

    print(output_text)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text)
        except Exception as exc:
            sys.stderr.write(f"Error writing benchmark report to {args.output}: {exc}\n")
            return 2

    # Exit code 0 if defended EMAR is 0.0%, exit code 1 if invariants were breached
    return 0 if report.defended.emar == 0.0 else 1


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for agentpoi-sde CLI."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.subcommand == "anchor":
        return handle_anchor(args)
    if args.subcommand == "check-diff":
        return handle_check_diff(args)
    if args.subcommand == "benchmark":
        return handle_benchmark(args)

    return 2


if __name__ == "__main__":
    sys.exit(main())
