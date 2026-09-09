# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Deterministic release-builder contract tests."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

from awq.release import (
    BUILD_CONSTRAINTS_PATH,
    REGISTRY_PATHS,
    REQUIRED_SCHEMAS,
    ReleaseError,
    build_constraints_digest,
    source_identity,
)
from scripts import build_release as builder
from tests.support import Repository


class ReleaseBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.scratch = self.root / "scratch"
        self.cache = self.root / "cache"
        self.output = self.root / "release"
        self.source.mkdir()
        self.scratch.mkdir()
        self.cache.mkdir()
        self.source.joinpath("pyproject.toml").write_text(
            '[build-system]\nrequires = ["hatchling==1.27.0"]\n'
            'build-backend = "hatchling.build"\n\n'
            '[project]\nname = "agent-workflow-quality"\nversion = "0.13.0"\n',
            encoding="utf-8",
        )
        for relative in REGISTRY_PATHS.values():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        constraints = self.source / BUILD_CONSTRAINTS_PATH
        constraints.parent.mkdir(parents=True, exist_ok=True)
        constraints.write_bytes((Path(__file__).parents[1] / BUILD_CONSTRAINTS_PATH).read_bytes())
        self.uv = self.root / "uv"
        self.uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.uv.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_sdist_excludes_hostile_privacy_fixture(self) -> None:
        document = tomllib.loads(
            Path(__file__).parents[1].joinpath("pyproject.toml").read_text(encoding="utf-8")
        )
        excluded = document["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"]
        self.assertIn("/fixtures/broken/privacy/leak.txt", excluded)

    @staticmethod
    def identity() -> dict[str, object]:
        return {
            "repository": "https://github.com/martin-beck/agent-workflow-quality",
            "commit": "a" * 40,
            "tree": "b" * 40,
            "source_date_epoch": 1_788_930_927,
        }

    @staticmethod
    def distribution_bytes(marker: bytes = b"same") -> tuple[bytes, bytes]:
        epoch = 1_788_930_927
        zip_time = (2026, 9, 9, 5, 15, 26)
        wheel_stream = io.BytesIO()
        with zipfile.ZipFile(wheel_stream, mode="w") as archive:
            members = {
                "agent_workflow_quality-0.13.0.dist-info/METADATA": (
                    b"Name: agent-workflow-quality\nVersion: 0.13.0\n"
                ),
                "awq/data/adapter_catalog.json": b"{}\n",
                "awq/build-marker": marker,
                **{f"awq/schemas/{name}": b"{}\n" for name in REQUIRED_SCHEMAS},
            }
            for name, content in members.items():
                zip_item = zipfile.ZipInfo(name, date_time=zip_time)
                zip_item.create_system = 3
                zip_item.external_attr = (0o644 if ".dist-info/" in name else 0o100644) << 16
                zip_item.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(zip_item, content)
        source_stream = io.BytesIO()
        prefix = "agent_workflow_quality-0.13.0"
        with tarfile.open(fileobj=source_stream, mode="w:gz") as archive:
            members = {
                f"{prefix}/pyproject.toml": (
                    b'[project]\nname = "agent-workflow-quality"\nversion = "0.13.0"\n'
                ),
                f"{prefix}/src/awq/data/adapter_catalog.json": b"{}\n",
                f"{prefix}/build-marker": marker,
                **{f"{prefix}/schemas/{name}": b"{}\n" for name in REQUIRED_SCHEMAS},
            }
            for name, content in members.items():
                tar_item = tarfile.TarInfo(name)
                tar_item.size = len(content)
                tar_item.mtime = epoch
                tar_item.mode = 0o644
                archive.addfile(tar_item, io.BytesIO(content))
        return wheel_stream.getvalue(), source_stream.getvalue()

    def test_environment_is_exact_minimal_offline_and_reproducible(self) -> None:
        environment = builder._environment(self.cache, self.scratch, 1_788_930_927)
        self.assertEqual(
            {
                "HOME",
                "LANG",
                "LC_ALL",
                "PATH",
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONHASHSEED",
                "SOURCE_DATE_EPOCH",
                "TMPDIR",
                "TZ",
                "UV_CACHE_DIR",
                "UV_LINK_MODE",
                "UV_NO_PROGRESS",
                "UV_OFFLINE",
                "UV_PYTHON_DOWNLOADS",
            },
            set(environment),
        )
        self.assertEqual("1", environment["UV_OFFLINE"])
        self.assertEqual("never", environment["UV_PYTHON_DOWNLOADS"])
        self.assertEqual("/nonexistent", environment["HOME"])
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertFalse(any("PROXY" in name for name in environment))

    def test_project_metadata_constraints_and_exact_paths_fail_closed(self) -> None:
        self.assertEqual(("0.13.0", "1.27.0"), builder._project_versions(self.source))
        build_constraints_digest(self.source)
        self.assertEqual(self.source, builder._exact_directory(self.source, "source"))
        self.assertEqual(self.output, builder._output_path(self.output, self.source))
        with self.assertRaisesRegex(builder.BuildError, "new external"):
            builder._output_path(Path("relative"), self.source)
        with self.assertRaisesRegex(builder.BuildError, "new external"):
            builder._output_path(self.source / "dist", self.source)
        self.output.mkdir()
        with self.assertRaisesRegex(builder.BuildError, "new external"):
            builder._output_path(self.output, self.source)
        self.source.joinpath("pyproject.toml").write_text(
            '[build-system]\nrequires = ["hatchling==1.27.0"]\n'
            'build-backend = "other.backend"\nbackend-path = []\n'
            '[project]\nversion = "0.13.0"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(builder.BuildError, "versions are not exact"):
            builder._project_versions(self.source)
        constraints = self.source / BUILD_CONSTRAINTS_PATH
        constraints.write_bytes(constraints.read_bytes() + b"# changed\n")
        with self.assertRaisesRegex(ReleaseError, "differ"):
            build_constraints_digest(self.source)

    def test_uv_probe_accepts_only_exact_bounded_version_output(self) -> None:
        def probe(returncode: int, output: bytes) -> Any:
            def run(argv: list[str], **kwargs: Any) -> int:
                del argv
                kwargs["stdout"].write(output)
                return returncode

            return run

        with mock.patch(
            "scripts.build_release._run_bounded",
            side_effect=probe(0, b"uv 0.12.8 (x86_64-unknown-linux-gnu)\n"),
        ) as run:
            self.assertEqual(self.uv, builder._uv_executable(self.uv, self.scratch))
            self.assertEqual([str(self.uv), "--version"], run.call_args.args[0])
            self.assertEqual(30, run.call_args.kwargs["timeout"])
        for returncode, output in (
            (1, b""),
            (0, b"uv 9.9.9 (x86_64-unknown-linux-gnu)\n"),
            (0, b"x" * 201),
            (0, b"\xff"),
        ):
            with (
                self.subTest(returncode=returncode, output=output),
                mock.patch(
                    "scripts.build_release._run_bounded",
                    side_effect=probe(returncode, output),
                ),
                self.assertRaises(builder.BuildError),
            ):
                builder._uv_executable(self.uv, self.scratch)
        with self.assertRaisesRegex(builder.BuildError, "unavailable"):
            builder._uv_executable(self.root / "missing", self.scratch)

    def test_bounded_runner_kills_the_process_group_on_timeout(self) -> None:
        process = mock.Mock(pid=123)
        process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd=["tool"], timeout=1),
            0,
        ]
        with (
            mock.patch("scripts.build_release.subprocess.Popen", return_value=process) as popen,
            mock.patch("scripts.build_release.os.killpg") as kill,
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            builder._run_bounded(["tool"], timeout=1)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        kill.assert_called_once_with(123, signal.SIGKILL)
        self.assertEqual(2, process.wait.call_count)

    def test_build_once_uses_fixed_argv_environment_and_normalizes_failure(self) -> None:
        target = self.root / "one"
        with mock.patch("scripts.build_release._run_bounded", return_value=0) as run:
            builder._build_once(
                self.uv,
                self.source,
                target,
                self.cache,
                self.scratch,
                1_788_930_927,
            )
        argv = run.call_args.args[0]
        self.assertEqual(str(self.uv), argv[0])
        self.assertEqual("build", argv[1])
        for required in (
            "--offline",
            "--no-build-logs",
            "--no-sources",
            "--no-python-downloads",
            "--no-create-gitignore",
            "--no-config",
            "--require-hashes",
            "--build-constraints",
        ):
            self.assertIn(required, argv)
        self.assertIn(str(self.source / BUILD_CONSTRAINTS_PATH), argv)
        self.assertIn(sys.executable, argv)
        self.assertNotIn("--no-build-isolation", argv)
        self.assertEqual(builder.BUILD_TIMEOUT_SECONDS, run.call_args.kwargs["timeout"])
        self.assertEqual("1", run.call_args.kwargs["env"]["UV_OFFLINE"])
        with (
            mock.patch("scripts.build_release._run_bounded", return_value=1),
            self.assertRaisesRegex(builder.BuildError, "offline distribution build failed"),
        ):
            builder._build_once(
                self.uv,
                self.source,
                self.root / "two",
                self.cache,
                self.scratch,
                1_788_930_927,
            )

    def test_distribution_shape_archive_gate_and_byte_comparison(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        first.mkdir()
        second.mkdir()
        wheel, sdist = self.distribution_bytes()
        names = builder._expected_names("0.13.0")
        for directory in (first, second):
            directory.joinpath(names["wheel"]).write_bytes(wheel)
            directory.joinpath(names["sdist"]).write_bytes(sdist)
        observed_first = builder._distributions(first, "0.13.0")
        observed_second = builder._distributions(second, "0.13.0")
        builder._compare(observed_first, observed_second)
        second.joinpath(names["wheel"]).write_bytes(self.distribution_bytes(b"different")[0])
        observed_second = builder._distributions(second, "0.13.0")
        with self.assertRaisesRegex(builder.BuildError, "wheel output"):
            builder._compare(observed_first, observed_second)
        first.joinpath("extra").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(builder.BuildError, "outputs differ"):
            builder._distributions(first, "0.13.0")
        first.joinpath("extra").unlink()
        with (
            mock.patch("scripts.build_release.inspect_archive", return_value=["unsafe"]),
            self.assertRaisesRegex(builder.BuildError, "archive verification"),
        ):
            builder._distributions(first, "0.13.0")

    def test_git_snapshot_excludes_untracked_and_preserves_mode(self) -> None:
        repository = Repository()
        try:
            repository.write("tracked.txt", "tracked\n")
            repository.write("tools/run", "#!/bin/sh\n", executable=True)
            repository.commit()
            identity = source_identity(repository.root)
            epoch = identity["source_date_epoch"]
            assert isinstance(epoch, int)
            repository.write("UNTRACKED.txt", "must not enter snapshot\n")
            snapshot = self.root / "snapshot"
            builder._materialize_source(repository.root, snapshot, epoch)
            self.assertEqual("tracked\n", snapshot.joinpath("tracked.txt").read_text())
            self.assertFalse(snapshot.joinpath("UNTRACKED.txt").exists())
            self.assertFalse(snapshot.joinpath(".git").exists())
            self.assertEqual(0o755, snapshot.joinpath("tools/run").stat().st_mode & 0o777)
        finally:
            repository.close()

    def test_full_orchestration_double_builds_and_atomically_publishes(self) -> None:
        wheel, sdist = self.distribution_bytes()
        names = builder._expected_names("0.13.0")
        seen_sources: set[str] = set()

        def materialize(source: Path, target: Path, epoch: int) -> None:
            self.assertEqual(self.source, source)
            self.assertEqual(1_788_930_927, epoch)
            shutil.copytree(source, target, ignore=shutil.ignore_patterns("UNTRACKED.txt"))

        def build_once(
            uv: Path,
            source: Path,
            output: Path,
            cache: Path,
            temporary: Path,
            epoch: int,
        ) -> None:
            del uv, cache, temporary
            self.assertEqual(1_788_930_927, epoch)
            self.assertFalse(source.joinpath("UNTRACKED.txt").exists())
            seen_sources.add(source.name)
            output.mkdir()
            output.joinpath(names["wheel"]).write_bytes(wheel)
            output.joinpath(names["sdist"]).write_bytes(sdist)

        self.source.joinpath("UNTRACKED.txt").write_text("noise\n", encoding="utf-8")
        with (
            mock.patch("scripts.build_release._uv_executable", return_value=self.uv),
            mock.patch("scripts.build_release.source_identity", return_value=self.identity()),
            mock.patch("awq.release.source_identity", return_value=self.identity()),
            mock.patch(
                "scripts.build_release.platform.python_version",
                return_value=builder.PYTHON_VERSION,
            ),
            mock.patch(
                "scripts.build_release._materialize_source", side_effect=materialize
            ) as snapshots,
            mock.patch("scripts.build_release._build_once", side_effect=build_once) as builds,
        ):
            result = builder.build_release(
                self.source, self.output, self.scratch, self.cache, self.uv
            )
        self.assertEqual(2, snapshots.call_count)
        self.assertEqual(2, builds.call_count)
        self.assertEqual({"source-first", "source-second"}, seen_sources)
        self.assertEqual("pass", result["status"])
        self.assertEqual(
            {
                names["wheel"],
                names["sdist"],
                "agent_workflow_quality-0.13.0.release.json",
            },
            {item.name for item in self.output.iterdir()},
        )
        document = json.loads(
            self.output.joinpath("agent_workflow_quality-0.13.0.release.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(builder.PYTHON_VERSION, document["builder"]["python_version"])
        self.assertEqual(
            build_constraints_digest(self.source),
            document["builder"]["build_constraints_sha256"],
        )
        self.assertEqual(self.identity(), document["source"])

    def test_host_atomic_no_replace_and_stage_failures_leave_inputs_intact(self) -> None:
        with (
            mock.patch("scripts.build_release._uv_executable", return_value=self.uv),
            mock.patch("scripts.build_release.source_identity", return_value=self.identity()),
            mock.patch("scripts.build_release.platform.python_version", return_value="9.9.9"),
            self.assertRaisesRegex(builder.BuildError, "Python version"),
        ):
            builder.build_release(self.source, self.output, self.scratch, self.cache, self.uv)
        self.assertFalse(self.output.exists())

        staged = self.root / "staged"
        competing = self.root / "competing"
        staged.mkdir()
        competing.mkdir()
        staged.joinpath("ours").write_text("ours", encoding="utf-8")
        competing.joinpath("theirs").write_text("theirs", encoding="utf-8")
        with self.assertRaises(OSError):
            builder._rename_noreplace(staged, competing)
        self.assertTrue(staged.joinpath("ours").is_file())
        self.assertTrue(competing.joinpath("theirs").is_file())

        source_dir = self.root / "built"
        source_dir.mkdir()
        wheel, sdist = self.distribution_bytes()
        names = builder._expected_names("0.13.0")
        distributions = {}
        for kind, payload in (("wheel", wheel), ("sdist", sdist)):
            target = source_dir / names[kind]
            target.write_bytes(payload)
            distributions[kind] = target
        with (
            mock.patch(
                "scripts.build_release.verify_release",
                side_effect=ReleaseError("private detail"),
            ),
            self.assertRaises(ReleaseError),
        ):
            builder._stage_bundle(
                self.source,
                self.output,
                distributions,
                {
                    "version": "0.13.0",
                    "source": self.identity(),
                    "builder": {},
                    "registries": {},
                    "artifacts": [],
                },
            )
        self.assertFalse(self.output.exists())
        self.assertEqual([], list(self.root.glob(".release-*")))

    def test_main_emits_canonical_success_or_content_minimized_failure(self) -> None:
        success = {"status": "pass", "version": "0.13.0"}
        output = io.StringIO()
        with (
            mock.patch("scripts.build_release.build_release", return_value=success),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                0,
                builder.main(
                    [
                        "--source",
                        str(self.source),
                        "--output",
                        str(self.output),
                        "--scratch",
                        str(self.scratch),
                        "--uv-cache",
                        str(self.cache),
                        "--uv",
                        str(self.uv),
                    ]
                ),
            )
        self.assertEqual('{"status":"pass","version":"0.13.0"}\n', output.getvalue())

        output = io.StringIO()
        with (
            mock.patch(
                "scripts.build_release.build_release",
                side_effect=builder.BuildError("secret " + "/home/" + "alice/"),
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                1,
                builder.main(
                    [
                        "--output",
                        str(self.output),
                        "--scratch",
                        str(self.scratch),
                        "--uv-cache",
                        str(self.cache),
                        "--uv",
                        str(self.uv),
                    ]
                ),
            )
        self.assertEqual("release build failed\n", output.getvalue())


if __name__ == "__main__":
    unittest.main()
