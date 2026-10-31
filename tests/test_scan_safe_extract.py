"""Tests for agentpoi_scan.fetch.safe_extract — the no-execution structural core."""

import io
import tarfile

import pytest

from agentpoi_scan.fetch.safe_extract import ExtractionError, extract_snapshot


def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            blob = data.encode("utf-8")
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))
    return buf.getvalue()


def _plain_tar(prefix="repo-x/"):
    return _tar(
        [
            (f"{prefix}src/app.py", "print('hi')\n"),
            (f"{prefix}README.md", "# readme\n"),
            (f"{prefix}deep/nested/path/file.py", "x = 1\n"),
        ]
    )


def test_extracts_regular_files_with_manifest(tmp_path):
    manifest = extract_snapshot(_plain_tar(), tmp_path)
    assert (tmp_path / "src" / "app.py").read_text() == "print('hi')\n"
    assert manifest.files["src/app.py"] == len("print('hi')\n")
    assert len(manifest.files) == 3
    assert set(manifest.sha256) == set(manifest.files)
    assert manifest.skipped == []
    assert manifest.text_files == ["README.md", "deep/nested/path/file.py", "src/app.py"]


def test_symlink_and_device_members_are_skipped_not_created(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="repo-x/src/app.py")
        blob = b"print('hi')\n"
        info.size = len(blob)
        tf.addfile(info, io.BytesIO(blob))

        link = tarfile.TarInfo(name="repo-x/link.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        link.size = 0
        tf.addfile(link)

    manifest = extract_snapshot(buf.getvalue(), tmp_path)
    assert manifest.files == {"src/app.py": len(blob)}
    assert manifest.skipped == [("link.py", "symlink")]
    assert not (tmp_path / "link.py").exists()
    assert not (tmp_path / "etc").exists()


def test_absolute_path_member_raises(tmp_path):
    evil = _tar([("/etc/cron.d/evil", "x")])
    with pytest.raises(ExtractionError, match="absolute"):
        extract_snapshot(evil, tmp_path)


def test_traversal_member_raises(tmp_path):
    evil = _tar([("repo-x/../../escape.py", "x")])
    with pytest.raises(ExtractionError, match="traversal"):
        extract_snapshot(evil, tmp_path)


def test_depth_cap_enforced(tmp_path):
    deep = _tar([("repo-x/" + "/".join(f"d{i}" for i in range(30)) + "/f.py", "x")])
    with pytest.raises(ExtractionError, match="depth"):
        extract_snapshot(deep, tmp_path, max_depth=20)


def test_file_count_cap_raises(tmp_path):
    many = _tar([(f"repo-x/f{i}.py", "x") for i in range(10)])
    with pytest.raises(ExtractionError, match="file count"):
        extract_snapshot(many, tmp_path, max_files=5)


def test_total_size_cap_raises(tmp_path):
    big = _tar([("repo-x/big.bin", "A" * (2 * 1024 * 1024))])  # 2 MB payload
    with pytest.raises(ExtractionError, match="total size"):
        extract_snapshot(big, tmp_path, max_total_mb=1)


def test_exec_bits_are_po644(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="repo-x/setup.py")
        blob = b"print('x')\n"
        info.size = len(blob)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(blob))
    extract_snapshot(buf.getvalue(), tmp_path)
    # chmod is a no-op on Windows; assert when meaningful (POSIX)
    import os
    if os.name != "nt":
        assert ((tmp_path / "setup.py").stat().st_mode & 0o111) == 0


def test_binary_candidates_classification(tmp_path):
    mixed = _tar(
        [
            ("repo-x/app.py", "print('hi')\n"),
            ("repo-x/payload.exe", "MZ\x00\x00"),
            ("repo-x/lib.so", "\x7fELF\x00"),
        ]
    )
    manifest = extract_snapshot(mixed, tmp_path)
    assert manifest.binary_candidates == ["lib.so", "payload.exe"]
    assert "app.py" in manifest.text_files


def test_git_entries_and_gitmodules_skipped(tmp_path):
    tar = _tar([
        ("repo-x/src/app.py", "x = 1\n"),
        ("repo-x/.gitmodules", "[submodule \"lib\"]\n  path = lib\n"),
        ("repo-x/.git/config", "[core]\n"),
        ("repo-x/.github/workflows/ci.yml", "name: CI\n"),
    ])
    manifest = extract_snapshot(tar, tmp_path)
    assert "src/app.py" in manifest.files
    assert ".github/workflows/ci.yml" in manifest.files
    assert ".gitmodules" not in manifest.files
    assert not any(f.startswith(".git/") for f in manifest.files)
    assert not (tmp_path / ".gitmodules").exists()
    assert not (tmp_path / ".git").exists()

