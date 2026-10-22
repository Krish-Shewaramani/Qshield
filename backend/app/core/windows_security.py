"""Apply restrictive permissions to local application data directories."""

from __future__ import annotations

import csv
from functools import lru_cache
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


_SID_RE = re.compile(r"^S-1-(?:\d+-)+\d+$")
_ACE_RE = re.compile(r"\(([^()]*)\)")


def ensure_private_directory(directory: Path) -> None:
    """Create a directory accessible only to the current user and SYSTEM.

    Fails closed on Windows if the ACL cannot be applied. This protects data at
    rest from other local accounts; it does not protect against the current
    account, administrators, malware running as that account, or backups.
    """
    path = Path(directory).resolve()
    _ensure_private_directory_cached(path)


@lru_cache(maxsize=64)
def _ensure_private_directory_cached(path: Path) -> None:
    """Avoid launching Windows ACL utilities for every API request."""
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            path.chmod(0o700)
        except OSError as exc:
            raise OSError("could not restrict application data directory permissions") from exc
        return

    whoami = shutil.which("whoami.exe") or shutil.which("whoami")
    icacls = shutil.which("icacls.exe") or shutil.which("icacls")
    if whoami is None or icacls is None:
        raise OSError("required Windows ACL utilities are unavailable")
    try:
        identity = subprocess.run(
            [whoami, "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            timeout=10,
        )
        row = next(csv.reader(identity.stdout.splitlines()))
        sid = row[-1].strip()
        if not _SID_RE.fullmatch(sid):
            raise ValueError("invalid SID")
        # /inheritance:r removes inherited ACEs, not unrelated explicit ACEs.
        # /reset first replaces the DACL with inherited defaults; removing those
        # inherited entries then leaves a clean DACL to populate below.
        subprocess.run(
            [icacls, str(path), "/reset"],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            timeout=10,
        )
        subprocess.run(
            [icacls, str(path), "/inheritance:r"],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            timeout=10,
        )
        subprocess.run(
            [
                icacls,
                str(path),
                "/grant:r",
                f"*{sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            timeout=10,
        )
        _verify_directory_acl(icacls, path, sid)
    except (OSError, subprocess.SubprocessError, StopIteration, ValueError, IndexError) as exc:
        raise OSError("could not apply restrictive Windows ACL to application data directory") from exc


def _verify_directory_acl(icacls: str, directory: Path, sid: str) -> None:
    """Verify the protected DACL contains only inheritable user and SYSTEM grants."""
    descriptor, temporary_name = tempfile.mkstemp(prefix="qshield-acl-", suffix=".txt")
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        subprocess.run(
            [icacls, str(directory), "/save", str(temporary_path)],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
            timeout=10,
        )
        # icacls /save writes UTF-16 little-endian without a byte-order mark.
        saved = temporary_path.read_text(encoding="utf-16-le")
        dacl_start = saved.find("D:")
        if dacl_start < 0:
            raise ValueError("directory DACL could not be read")
        dacl = saved[dacl_start:].splitlines()[0]
        if not dacl.startswith("D:P"):
            raise ValueError("directory DACL is not protected from inheritance")
        aces = [ace.split(";") for ace in _ACE_RE.findall(dacl)]
        expected = {
            ("A", "OICI", "FA", "", "", sid),
            ("A", "OICI", "FA", "", "", "SY"),
        }
        if len(aces) != 2 or {tuple(ace) for ace in aces} != expected:
            raise ValueError("directory DACL contains unexpected permissions")
    finally:
        temporary_path.unlink(missing_ok=True)
