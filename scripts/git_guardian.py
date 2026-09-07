#!/usr/bin/env python3
"""Git Guardian Pre-Commit Hook.

Blocks commits containing developer-only or never-track files.
Enforces Rule 6 (Public vs. Developer Abstraction Quarantine) at the git level.

Installation (choose one):
  1. Copy to .git/hooks/pre-commit  (make executable on Linux/Mac)
  2. Run standalone: python scripts/git_guardian.py
  3. Use with pre-commit framework: add to .pre-commit-config.yaml

Usage:
  python scripts/git_guardian.py           # Audit staged files
  python scripts/git_guardian.py --audit   # Audit ALL tracked files
  python scripts/git_guardian.py --report  # Full classification report
"""

import argparse
import os
import sys

# Ensure workspace root is in sys.path
workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if workspace_root not in sys.path:
    sys.path.insert(0, workspace_root)

# Set stdout/stderr to UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from agent_poi.core.file_classifier import (
    FileClass,
    audit_git_staging,
    audit_tracked_files,
    get_classification_report,
)


def check_staged_files() -> int:
    """Check staged files for non-public content. Returns exit code."""
    violations = audit_git_staging(workspace_root)

    if not violations:
        print("✅ Git Guardian: All staged files are PUBLIC — commit allowed.")
        return 0

    print("=" * 70)
    print(" GIT GUARDIAN: COMMIT BLOCKED — Non-public files detected")
    print("=" * 70)

    never_track = [(f, c, m) for f, c, m in violations if c == FileClass.NEVER_TRACK]
    dev_only = [(f, c, m) for f, c, m in violations if c == FileClass.DEVELOPER_ONLY]

    if never_track:
        print()
        print(f"  🚫 NEVER_TRACK files ({len(never_track)}):")
        for filepath, _, _ in never_track:
            print(f"     🚫 {filepath}")

    if dev_only:
        print()
        print(f"  ⚠️  DEVELOPER_ONLY files ({len(dev_only)}):")
        for filepath, _, _ in dev_only:
            print(f"     ⚠️  {filepath}")

    print()
    print("  Fix: git reset HEAD <file> to unstage these files.")
    print("  Or:  git reset HEAD -- $(git diff --cached --name-only)")
    print("=" * 70)
    return 1


def check_tracked_files() -> int:
    """Audit all tracked files for non-public content."""
    violations = audit_tracked_files(workspace_root)

    if not violations:
        print("✅ Git Guardian Audit: All tracked files are PUBLIC — repository clean.")
        return 0

    print("=" * 70)
    print(f" GIT GUARDIAN AUDIT: {len(violations)} non-public files found in git history")
    print("=" * 70)

    for filepath, cls, msg in violations:
        icon = "🚫" if cls == FileClass.NEVER_TRACK else "⚠️"
        print(f"  {icon} [{cls.value:15s}] {filepath}")

    print()
    print("  Fix: git rm --cached <file> to untrack without deleting locally.")
    print("=" * 70)
    return 1


def main() -> int:
    """Entry point for Git Guardian."""
    parser = argparse.ArgumentParser(
        description="Git Guardian — File Classification Enforcement",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Audit ALL tracked files (not just staged)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print full classification report",
    )
    args = parser.parse_args()

    if args.report:
        print(get_classification_report(workspace_root))
        return 0

    if args.audit:
        return check_tracked_files()

    return check_staged_files()


if __name__ == "__main__":
    sys.exit(main())
