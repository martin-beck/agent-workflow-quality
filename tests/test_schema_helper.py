# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Unit tests for the bounded schema helper."""

from __future__ import annotations

import contextlib
import importlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from awq import schema_helper as helper


class SchemaHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_strict_json_rejects_duplicates_constants_and_bad_paths(self) -> None:
        self.write("valid.json", '{"key": 1}\n')
        budget = helper.ReadBudget()
        self.assertEqual({"key": 1}, helper._json_document(self.root, "valid.json", budget))
        self.assertEqual(11, budget.total)
        helper._json_document(self.root, "valid.json", budget)
        self.assertEqual(11, budget.total)

        for name, content in (
            ("duplicate.json", '{"key": 1, "key": 2}\n'),
            ("constant.json", '{"key": NaN}\n'),
        ):
            self.write(name, content)
            with self.subTest(name=name), self.assertRaises(ValueError):
                helper._json_document(self.root, name, helper.ReadBudget())

        for name in ("../outside.json", r"bad\path.json", "/absolute.json", "missing.json"):
            with self.subTest(name=name), self.assertRaises(helper.SchemaCheckError):
                helper._json_document(self.root, name, helper.ReadBudget())

    def test_read_budget_rejects_individual_and_aggregate_excess(self) -> None:
        self.write("one.json", "{}")
        self.write("two.json", "{}")
        with (
            mock.patch.object(helper, "MAX_FILE_BYTES", 1),
            self.assertRaisesRegex(helper.SchemaCheckError, "size"),
        ):
            helper.ReadBudget().read(self.root, "one.json")
        with (
            mock.patch.object(helper, "MAX_TOTAL_BYTES", 3),
            self.assertRaisesRegex(helper.SchemaCheckError, "size"),
        ):
            budget = helper.ReadBudget()
            budget.read(self.root, "one.json")
            budget.read(self.root, "two.json")

    def test_strict_yaml_rejects_duplicates_tags_anchors_and_flow(self) -> None:
        self.write("valid.yaml", "key: value\nitems:\n- one\n")
        helper._yaml_document(self.root, "valid.yaml", helper.ReadBudget())
        cases = {
            "duplicate.yaml": "key: one\nkey: two\n",
            "tag.yaml": "key: !!python/object/apply:os.system ['id']\n",
            "anchor.yaml": "key: &value one\ncopy: *value\n",
            "flow.yaml": "key: [one, two]\n",
        }
        for name, content in cases.items():
            self.write(name, content)
            with self.subTest(name=name), self.assertRaises(helper.SchemaCheckError):
                helper._yaml_document(self.root, name, helper.ReadBudget())

    def test_schema_graph_accepts_recursive_local_refs_and_rejects_unsafe_refs(self) -> None:
        self.write(
            "schemas/root.schema.json",
            '{"$schema":"https://json-schema.org/draft/2020-12/schema",'
            '"properties":{"value":{"$ref":"defs.schema.json#/$defs/value"}}}\n',
        )
        self.write(
            "schemas/defs.schema.json",
            '{"$schema":"https://json-schema.org/draft/2020-12/schema",'
            '"$defs":{"value":{"type":"integer","$ref":"#/$defs/value"}}}\n',
        )
        helper._schema_graph(
            self.root,
            ["schemas/root.schema.json"],
            helper.ReadBudget(),
        )

        cases = {
            "remote.schema.json": "https://example.invalid/schema",
            "network-path.schema.json": "//example.invalid/schema",
            "query.schema.json": "defs.schema.json?revision=1",
            "missing.schema.json": "absent.schema.json",
            "wrong-suffix.schema.json": "../outside.json",
            "parent.schema.json": "../schemas/defs.schema.json",
        }
        self.write("outside.json", "{}\n")
        for name, reference in cases.items():
            self.write(
                f"schemas/{name}",
                '{"$schema":"https://json-schema.org/draft/2020-12/schema",'
                f'"$ref":"{reference}"}}\n',
            )
            with self.subTest(name=name), self.assertRaises(helper.SchemaCheckError):
                helper._schema_graph(
                    self.root,
                    [f"schemas/{name}"],
                    helper.ReadBudget(),
                )

        self.write(
            "limited.schema.json",
            '{"$schema":"https://json-schema.org/draft/2020-12/schema",'
            '"$ref":"schemas/defs.schema.json"}\n',
        )
        with (
            mock.patch.object(helper, "MAX_FILES", 1),
            self.assertRaisesRegex(helper.SchemaCheckError, "file count"),
        ):
            helper._schema_graph(
                self.root,
                ["limited.schema.json"],
                helper.ReadBudget(),
            )

    def test_validate_instances_preparses_every_format_and_invokes_exact_command(self) -> None:
        self.write(
            "project.schema.json",
            '{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}\n',
        )
        self.write("good.instance.json", "{}\n")
        self.write("good.instance.yaml", "key: value\n")
        with mock.patch.object(helper, "_invoke_jsonschema") as invoke:
            helper._validate_instances(
                self.root,
                "project.schema.json",
                ["good.instance.json", "good.instance.yaml"],
                helper.ReadBudget(),
            )
        invoke.assert_called_once_with(
            [
                "validate",
                "project.schema.json",
                "--format-assertion",
                "good.instance.json",
                "good.instance.yaml",
            ]
        )
        self.write("unsupported.txt", "value\n")
        with self.assertRaisesRegex(helper.SchemaCheckError, "unsupported"):
            helper._validate_instances(
                self.root,
                "project.schema.json",
                ["unsupported.txt"],
                helper.ReadBudget(),
            )

    def test_jsonschema_probe_and_execution_fail_closed(self) -> None:
        success = subprocess.CompletedProcess([], 0, "16.3.0\n", "")
        failure = subprocess.CompletedProcess([], 2, "", "private validator detail")
        with (
            mock.patch.object(helper, "_jsonschema_binary", return_value=Path("/tool")),
            mock.patch.object(importlib, "import_module"),
            mock.patch.object(subprocess, "run", return_value=success) as run,
        ):
            helper._verify_toolset()
        self.assertEqual(["/tool", "version"], run.call_args.args[0])
        self.assertNotIn("HOME", run.call_args.kwargs["env"])

        with (
            mock.patch.object(helper, "_jsonschema_binary", return_value=Path("/tool")),
            mock.patch.object(subprocess, "run", return_value=failure),
            self.assertRaises(helper.SchemaCheckError),
        ):
            helper._invoke_jsonschema(["metaschema", "schema.json"])

        with (
            mock.patch.object(helper, "_jsonschema_binary", return_value=Path("/tool")),
            mock.patch.object(importlib, "import_module"),
            mock.patch.object(subprocess, "run", return_value=failure),
            self.assertRaises(helper.SchemaCheckError),
        ):
            helper._verify_toolset()

    def test_main_normalizes_failures_without_source_content(self) -> None:
        self.write("private.yaml", "secret-value: !!unsafe value\n")
        with (
            contextlib.chdir(self.root),
            mock.patch.object(helper, "_verify_toolset"),
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(1, helper.main(["yaml", "private.yaml"]))
        self.assertEqual("awq-schema-check: validation failed\n", errors.getvalue())
        self.assertNotIn("secret-value", errors.getvalue())

        with mock.patch.object(helper, "_verify_toolset"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, helper.main(["--version"]))
            self.assertEqual(helper.VERSION_OUTPUT + "\n", output.getvalue())
            self.assertEqual(1, helper.main([]))
            self.assertEqual(1, helper.main(["unknown", "file"]))
        with (
            mock.patch.object(helper, "MAX_FILES", 1),
            mock.patch.object(helper, "_verify_toolset"),
        ):
            self.assertEqual(1, helper.main(["json", "one.json", "two.json"]))


if __name__ == "__main__":
    unittest.main()
