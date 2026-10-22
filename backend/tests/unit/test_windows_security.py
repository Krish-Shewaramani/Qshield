import os
import csv
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from shutil import which

from backend.app.core.windows_security import ensure_private_directory


@unittest.skipUnless(os.name == "nt", "Windows ACL test")
class WindowsDirectorySecurityTests(unittest.TestCase):
    def test_private_directory_acl_grants_current_user_and_system(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            protected = Path(temporary) / "runtime"
            ensure_private_directory(protected)
            identity = subprocess.run(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"],
                check=True,
                capture_output=True,
                text=True,
            )
            current_account = next(csv.reader(identity.stdout.splitlines()))[0]
            acl = subprocess.run(
                ["icacls.exe", str(protected)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            # icacls resolves the granted SIDs to account names in normal output.
            self.assertIn(current_account.casefold(), acl.casefold())
            self.assertIn("NT AUTHORITY\\SYSTEM".casefold(), acl.casefold())

    def test_existing_explicit_permissive_acl_is_removed_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            protected = Path(temporary) / "runtime"
            protected.mkdir()
            icacls = which("icacls.exe") or "icacls.exe"
            identity = subprocess.run(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"],
                check=True,
                capture_output=True,
                text=True,
            )
            current_sid = next(csv.reader(identity.stdout.splitlines()))[-1]

            # Add an explicit Everyone grant to an already existing directory.
            subprocess.run(
                [icacls, str(protected), "/grant", "*S-1-1-0:(OI)(CI)F"],
                check=True,
                capture_output=True,
                text=True,
            )
            before = _saved_dacl(icacls, protected)
            # SDDL uses the well-known alias WD for Everyone.
            self.assertIn(";;;WD)", before)

            ensure_private_directory(protected)

            after = _saved_dacl(icacls, protected)
            self.assertTrue(after.startswith("D:P"))
            self.assertNotIn(";;;WD)", after)
            aces = [tuple(ace.split(";")) for ace in re.findall(r"\(([^()]*)\)", after)]
            self.assertEqual(
                set(aces),
                {
                    ("A", "OICI", "FA", "", "", current_sid),
                    ("A", "OICI", "FA", "", "", "SY"),
                },
            )


def _saved_dacl(icacls: str, directory: Path) -> str:
    descriptor, name = tempfile.mkstemp(prefix="qshield-test-acl-", suffix=".txt")
    os.close(descriptor)
    path = Path(name)
    try:
        subprocess.run(
            [icacls, str(directory), "/save", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        saved = path.read_text(encoding="utf-16-le")
        start = saved.find("D:")
        if start < 0:
            raise AssertionError("icacls did not serialize the directory DACL")
        return saved[start:].splitlines()[0]
    finally:
        path.unlink(missing_ok=True)
