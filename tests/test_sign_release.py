# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Focused tests for the local release signing helper."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import sign_release


class SignReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "pyproject.toml").write_text(
            '[project]\nversion = "0.35.0"\n', encoding="utf-8"
        )
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.manifest = self.bundle / "agent_workflow_quality-0.35.0.release.json"
        self.manifest.write_bytes(b"canonical manifest\n")
        subprocess.run(["git", "init", "--quiet", str(self.source)], check=True)
        subprocess.run(["git", "-C", str(self.source), "config", "user.name", "Test"], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.source), "add", "pyproject.toml"], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "-c", "commit.gpgsign=false", "commit", "-m", "init"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.key = self.root / "release-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True
        )
        self.state = self.root / "state"
        (self.state / "tasks").mkdir(parents=True)
        (self.source / "config").mkdir()
        public = (self.key.with_name(self.key.name + ".pub")).read_text(encoding="ascii").strip()
        key_type, key_blob = public.split()[:2]
        (self.source / "config" / "allowed_signers").write_text(
            f"24471267+martin-beck@users.noreply.github.com {key_type} {key_blob}\n",
            encoding="ascii",
        )
        task = {
            "status": "open",
            "owner": "",
            "claim_expires": "",
            "observed_head": "",
            "observed_dirty": 0,
            "next_action": "Authorized external signer must sign the release",
        }
        subprocess.run(["git", "-C", str(self.source), "add", "config/allowed_signers"], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "-c", "commit.gpgsign=false", "commit", "-m", "policy"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        task["observed_head"] = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        (self.state / "tasks" / "AR-0054.md").write_text(
            "---\n" + __import__("json").dumps(task) + "\n---\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_dry_run_checks_key_separation_and_defaults(self) -> None:
        with mock.patch.object(sign_release, "_verify_manifest"):
            result = sign_release.sign_release(
                self.source,
                self.bundle,
                self.key,
                state_repo=self.state,
                allowed_signers=self.source / "config" / "allowed_signers",
                confirm=False,
            )
        self.assertEqual(result["version"], "0.35.0")
        self.assertEqual(result["tag"], "v0.35.0")
        self.assertEqual(len(result["manifest_sha256"]), 64)
        self.assertFalse((self.manifest.with_name(self.manifest.name + ".sig")).exists())

    def test_rejects_key_used_for_ordinary_commits(self) -> None:
        subprocess.run(
            ["git", "-C", str(self.source), "config", "user.signingkey", str(self.key) + ".pub"],
            check=True,
        )
        with (
            self.assertRaisesRegex(sign_release.SigningError, "ordinary commits"),
            mock.patch.object(sign_release, "_verify_manifest"),
        ):
            sign_release.sign_release(
                self.source,
                self.bundle,
                self.key,
                state_repo=self.state,
                allowed_signers=self.source / "config/allowed_signers",
            )

    def test_rejects_non_github_ssh_key_type(self) -> None:
        rsa = self.root / "rsa-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "dsa", "-N", "", "-f", str(rsa)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if rsa.exists():
            with (
                self.assertRaisesRegex(sign_release.SigningError, "accepted by GitHub"),
                mock.patch.object(sign_release, "_verify_manifest"),
            ):
                sign_release.sign_release(
                    self.source,
                    self.bundle,
                    rsa,
                    state_repo=self.state,
                    allowed_signers=self.source / "config/allowed_signers",
                )

    def test_rejects_key_not_in_reviewed_github_policy(self) -> None:
        other = self.root / "other-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)], check=True
        )
        with (
            self.assertRaisesRegex(sign_release.SigningError, "reviewed GitHub signing key"),
            mock.patch.object(sign_release, "_verify_manifest"),
        ):
            sign_release.sign_release(
                self.source,
                self.bundle,
                other,
                state_repo=self.state,
                allowed_signers=self.source / "config/allowed_signers",
            )
        self.assertFalse((self.manifest.with_name(self.manifest.name + ".sig")).exists())
        self.assertEqual(
            subprocess.run(
                ["git", "-C", str(self.source), "tag", "--list", "v0.35.0"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout,
            "",
        )

    def test_refuses_existing_tag_or_signature(self) -> None:
        signature = self.manifest.with_name(self.manifest.name + ".sig")
        signature.write_bytes(b"existing")
        with (
            self.assertRaisesRegex(sign_release.SigningError, "signature already exists"),
            mock.patch.object(sign_release, "_verify_manifest"),
        ):
            sign_release.sign_release(
                self.source,
                self.bundle,
                self.key,
                state_repo=self.state,
                allowed_signers=self.source / "config/allowed_signers",
            )

    def test_cli_failure_explains_safe_next_step(self) -> None:
        with (
            mock.patch.object(
                sign_release,
                "sign_release",
                side_effect=sign_release.SigningError("candidate is not ready"),
            ),
            mock.patch("sys.stderr") as stderr,
        ):
            self.assertEqual(sign_release.main([]), 1)
        rendered = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("Release signing stopped: candidate is not ready.", rendered)
        self.assertIn("No manifest signature, tag, or push was authorized.", rendered)

    def test_run_kills_descendant_holding_stdout(self) -> None:
        code = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])"
        )
        with (
            mock.patch.object(sign_release, "TIMEOUT", 1),
            self.assertRaisesRegex(sign_release.SigningError, "timed out"),
        ):
            sign_release._run([sys.executable, "-c", code])

    def test_rejects_nonhex_state_head_before_any_side_effect(self) -> None:
        task_path = self.state / "tasks" / "AR-0054.md"
        task = __import__("json").loads(task_path.read_text(encoding="utf-8").split("---\n")[1])
        task["observed_head"] = "z" * 40
        task_path.write_text("---\n" + __import__("json").dumps(task) + "\n---\n", encoding="utf-8")
        with self.assertRaisesRegex(sign_release.SigningError, "exact candidate"):
            sign_release.sign_release(
                self.source,
                self.bundle,
                self.key,
                state_repo=self.state,
                allowed_signers=self.source / "config/allowed_signers",
            )
        self.assertFalse((self.manifest.with_name(self.manifest.name + ".sig")).exists())

    def test_preview_refuses_wrong_head_without_checkout(self) -> None:
        task_path = self.state / "tasks" / "AR-0054.md"
        task = __import__("json").loads(task_path.read_text(encoding="utf-8").split("---\n")[1])
        task["observed_head"] = "0" * 40
        task_path.write_text("---\n" + __import__("json").dumps(task) + "\n---\n", encoding="utf-8")
        original = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        with (
            self.assertRaisesRegex(sign_release.SigningError, "preview requires"),
            mock.patch.object(sign_release, "_verify_manifest"),
        ):
            sign_release.sign_release(
                self.source,
                self.bundle,
                self.key,
                state_repo=self.state,
                allowed_signers=self.source / "config/allowed_signers",
                confirm=False,
            )
        self.assertEqual(
            original,
            subprocess.check_output(
                ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
            ).strip(),
        )

    def test_tag_failure_removes_manifest_signature(self) -> None:
        real_run = sign_release._run

        def fail_tag(argv: list[str], *, cwd: Path | None = None) -> tuple[int, bytes]:
            if argv and argv[0] == "/usr/bin/git" and "tag" in argv and "-s" in argv:
                raise sign_release.SigningError("command unavailable or timed out")
            if argv and argv[0] == "/usr/bin/ssh-keygen" and "-Y" in argv:
                Path(argv[-1] + ".sig").write_bytes(b"synthetic signature")
                return 0, b""
            return real_run(argv, cwd=cwd)

        signature = self.manifest.with_name(self.manifest.name + ".sig")
        with (
            mock.patch.object(sign_release, "_verify_manifest"),
            mock.patch.object(sign_release, "_run", side_effect=fail_tag),
            self.assertRaisesRegex(sign_release.SigningError, "annotated SSH tag"),
        ):
            sign_release.sign_release(
                self.source,
                self.bundle,
                self.key,
                state_repo=self.state,
                allowed_signers=self.source / "config/allowed_signers",
                confirm=True,
            )
        self.assertFalse(signature.exists())
        self.assertEqual(
            subprocess.check_output(
                ["git", "-C", str(self.source), "tag", "--list", "v0.35.0"], text=True
            ),
            "",
        )

    def test_confirm_signs_manifest_and_creates_annotated_tag(self) -> None:
        signature = self.manifest.with_name(self.manifest.name + ".sig")
        with mock.patch.object(sign_release, "_verify_manifest"):
            result = sign_release.sign_release(
                self.source,
                self.bundle,
                self.key,
                state_repo=self.state,
                allowed_signers=self.source / "config/allowed_signers",
                confirm=True,
            )
        try:
            self.assertEqual("v0.35.0", result["tag"])
            self.assertTrue(signature.is_file())
            tag_type = subprocess.check_output(
                ["git", "-C", str(self.source), "cat-file", "-t", "v0.35.0"],
                text=True,
            ).strip()
            self.assertEqual("tag", tag_type)
        finally:
            signature.unlink(missing_ok=True)
            subprocess.run(
                ["git", "-C", str(self.source), "tag", "-d", "v0.35.0"],
                check=True,
                stdout=subprocess.DEVNULL,
            )

    def test_cli_uses_trivial_default_paths(self) -> None:
        expected = {
            "version": "0.35.0",
            "commit": "0" * 40,
            "manifest_sha256": "0" * 64,
            "signer_fingerprint": "SHA256:test",
            "tag": "v0.35.0",
        }
        with (
            mock.patch.object(sign_release, "sign_release", return_value=expected) as invoke,
            mock.patch("sys.stdout"),
            mock.patch("sys.stderr"),
            mock.patch("pathlib.Path.cwd", return_value=self.source),
        ):
            self.assertEqual(0, sign_release.main([]))
        args, kwargs = invoke.call_args
        self.assertEqual(self.source, args[0])
        self.assertEqual(Path("..") / "awq-release", args[1])
        self.assertEqual(Path("~/.ssh/awq-release-signing"), args[2])
        self.assertIsNone(kwargs["state_repo"])
        self.assertIsNone(kwargs["allowed_signers"])
