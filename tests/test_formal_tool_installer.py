# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for the checksum-pinned TLC installer."""

from __future__ import annotations

import hashlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import install_formal_tools as installer


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url


class FormalToolInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_download_is_bounded_by_source_redirect_digest_and_size(self) -> None:
        content = b"reviewed jar"
        artifact = installer.Artifact(
            "tool.jar",
            "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tool.jar",
            hashlib.sha256(content).hexdigest(),
        )
        destination = self.root / artifact.name
        with mock.patch.object(installer, "urlopen", return_value=Response(content, artifact.url)):
            installer.download(artifact, destination)
        self.assertEqual(content, destination.read_bytes())

        bad_source = installer.Artifact("bad", "http://example.invalid/tool", artifact.sha256)
        with self.assertRaisesRegex(installer.FormalToolInstallError, "unreviewed source"):
            installer.download(bad_source, self.root / "bad-source")
        for case, response, error in (
            ("redirect", Response(content, "https://example.invalid/tool"), "redirected"),
            ("digest", Response(b"different", artifact.url), "SHA-256"),
        ):
            target = self.root / case
            with (
                self.subTest(case=case),
                mock.patch.object(installer, "urlopen", return_value=response),
                self.assertRaisesRegex(installer.FormalToolInstallError, error),
            ):
                installer.download(artifact, target)
            self.assertFalse(target.with_suffix(target.suffix + ".part").exists())
        with (
            mock.patch.object(installer, "MAX_DOWNLOAD_BYTES", 3),
            mock.patch.object(installer, "urlopen", return_value=Response(b"four", artifact.url)),
            self.assertRaisesRegex(installer.FormalToolInstallError, "size bound"),
        ):
            installer.download(artifact, self.root / "large")

    def test_install_is_atomic_versioned_and_digest_bound(self) -> None:
        content = b"synthetic reviewed jar"
        artifact = installer.Artifact(
            "tla2tools.jar",
            installer.TLA_TOOLS.url,
            hashlib.sha256(content).hexdigest(),
        )

        def fake_download(selected: installer.Artifact, destination: Path) -> None:
            self.assertEqual(artifact, selected)
            destination.write_bytes(content)

        prefix = self.root / "formal-tools"
        with (
            mock.patch.object(installer, "TLA_TOOLS", artifact),
            mock.patch.object(installer, "download", side_effect=fake_download),
        ):
            installer.install(prefix)
        self.assertEqual(content, (prefix / "lib/tla2tools.jar").read_bytes())
        self.assertEqual(
            [
                "#!/usr/bin/env python3",
                "# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.",
                "# SPDX-License-Identifier: MIT",
            ],
            (prefix / "bin/tlc").read_text(encoding="utf-8").splitlines()[:3],
        )
        completed = subprocess.run(
            [str(prefix / "bin/tlc"), "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(0, completed.returncode)
        self.assertEqual("TLC 1.8.0", completed.stdout.strip())
        (prefix / "lib/tla2tools.jar").write_bytes(b"tampered")
        tampered = subprocess.run(
            [str(prefix / "bin/tlc"), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        self.assertEqual(126, tampered.returncode)
        with self.assertRaisesRegex(installer.FormalToolInstallError, "new path"):
            installer.install(prefix)

    def test_failed_install_leaves_no_published_prefix(self) -> None:
        prefix = self.root / "failed"
        with (
            mock.patch.object(
                installer,
                "download",
                side_effect=installer.FormalToolInstallError("expected failure"),
            ),
            self.assertRaisesRegex(installer.FormalToolInstallError, "expected failure"),
        ):
            installer.install(prefix)
        self.assertFalse(prefix.exists())

        missing_parent = self.root / "missing/child"
        with self.assertRaisesRegex(installer.FormalToolInstallError, "new path"):
            installer.install(missing_parent)


if __name__ == "__main__":
    unittest.main()
