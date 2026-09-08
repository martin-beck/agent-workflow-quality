"""Registry and confined project contract tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from awq.project import (
    ProjectError,
    confined_path,
    confined_root,
    load_project,
    make_policy,
    sha256_json,
    validate_lock,
    validate_policy,
    write_initialization,
)
from awq.registry import RegistryError, canonical_bytes, expand_profiles, load_registry
from tests.support import Repository, base_policy


class RegistryTests(unittest.TestCase):
    def test_registry_is_complete_and_stable(self) -> None:
        requirements, profiles, digest = load_registry()
        self.assertEqual(16, len(requirements))
        self.assertIn("core", profiles)
        self.assertEqual(64, len(digest))
        self.assertEqual(canonical_bytes({"b": 1, "a": 2}), b'{"a":2,"b":1}\n')

    def test_profile_expansion_rejects_unknown(self) -> None:
        self.assertIn("AWQ-CORE-001", expand_profiles(["core"]))
        with self.assertRaisesRegex(RegistryError, "unknown profiles"):
            expand_profiles(["missing"])


class ProjectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()

    def tearDown(self) -> None:
        self.repo.close()

    def test_confined_paths(self) -> None:
        root = confined_root(self.repo.root)
        self.assertEqual(root / "new.txt", confined_path(root, "new.txt"))
        with self.assertRaisesRegex(ProjectError, "unsafe"):
            confined_path(root, "../escape")
        with self.assertRaisesRegex(ProjectError, "unsafe"):
            confined_path(root, str(Path(root.anchor) / "escape"))

    def test_symlink_root_and_component_are_rejected(self) -> None:
        target = self.repo.root / "target"
        target.mkdir()
        link = self.repo.root / "link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ProjectError, "non-symlink"):
            confined_root(link)
        with self.assertRaisesRegex(ProjectError, "traverses"):
            confined_path(self.repo.root, "link/file")

    def test_policy_generation_loading_and_collision(self) -> None:
        policy, lock = make_policy(["privacy", "core"])
        files = write_initialization(self.repo.root, policy, lock)
        self.assertEqual(["quality/awq.json", "quality/awq.lock.json", "tools/awq"], files)
        loaded_policy, loaded_lock = load_project(self.repo.root)
        self.assertEqual(policy, loaded_policy)
        self.assertEqual(lock, loaded_lock)
        self.assertEqual(64, len(sha256_json(policy)))
        with self.assertRaisesRegex(ProjectError, "refuses to overwrite"):
            write_initialization(self.repo.root, policy, lock)

    def test_runtime_validators_reject_unknown_shapes(self) -> None:
        policy = base_policy()
        validate_policy(policy)
        for mutation in (
            {**policy, "extra": True},
            {**policy, "profiles": []},
            {**policy, "unknown_formats": "skip"},
            {**policy, "extensions": {}},
        ):
            with self.assertRaises(ProjectError):
                validate_policy(mutation)
        extension = {
            "id": "LOCAL-TEST",
            "tier": "pr",
            "argv": ["true"],
            "timeout_seconds": 4,
            "evidence": "contract-test",
            "limitation": "Synthetic.",
            "remediation": "Repair.",
            "formats": [".x"],
        }
        validate_policy({**policy, "extensions": [extension]})
        with self.assertRaises(ProjectError):
            validate_policy({**policy, "extensions": [{**extension, "timeout_seconds": 0}]})
        with self.assertRaises(ProjectError):
            validate_policy({**policy, "exceptions": [{"id": "incomplete"}]})
        validate_lock(
            {
                "schema_version": 1,
                "awq_version": "0.1.0",
                "registry_sha256": "0" * 64,
                "profiles": [],
                "requirements": [],
            }
        )
        with self.assertRaises(ProjectError):
            validate_lock({"schema_version": 1})
