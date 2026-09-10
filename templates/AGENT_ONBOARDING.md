# Agent onboarding instructions template

Read this project's contributor instructions and coordination task before mutation.
Use the project's coordinator for every authorized change. This recipe grants no
new authority and does not replace project-specific instructions or native gates.

1. Select an independently reviewed AWQ source commit or authenticated local wheel.
2. Choose the matching packaged offline runtime; provision its pinned inputs separately.
3. Run `diagnostics` and read every compatibility finding before any mutation.
4. Obtain explicit project scope approval, then run `adoption` and review generated files.
5. Run existing project-owned `native-gates` directly before the AWQ `shared-ci` stage.
6. Review terminology findings and bounded native mappings without weakening native gates.
7. Complete `review`; a policy diff or migration preview never authorizes an update.
8. Run each read-only release authentication step and inspect the dry-run lock diff.
9. Obtain separate lock-only approval before the authenticated update.
10. Create a credential-free fresh clone separately, then complete `fresh-clone` verification.
11. Record only bounded aggregate evidence and digests, never logs, prompts or private paths.

Use the packaged agent_recipes.json workflow, runtime records and argv arrays. Replace
placeholders as individual arguments without constructing a shell command. Empty native-gate
recipes mean project-owned execution, not permission to skip that stage. The installed AWQ
release documentation in ONBOARDING, NATIVE_GATE_MAPPINGS and PROVENANCE defines capability,
equivalence and trust limitations.
