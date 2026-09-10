# Agent onboarding instructions template

Read this project's contributor instructions and coordination task before mutation.
Use the project's coordinator for every authorized change. This recipe grants no
new authority and does not replace project-specific instructions or native gates.

1. Select an independently reviewed AWQ source commit or authenticated local wheel.
2. Run the packaged onboarding diagnostic using the selected Python environment.
3. Read compatibility findings; unsupported or not-probed capabilities remain blocked.
4. Inspect the project and preview core initialization without changing files.
5. Obtain explicit scope approval before initialization; review every generated file.
6. Keep existing domain tests and native CI. Do not infer equivalence from shadow CI.
7. Preview migrations using canonical reviewed metadata; never treat a preview as approval.
8. Authenticate a complete release bundle and inspect the exact dry-run lock diff before update.
9. Record only bounded aggregate evidence and digests, never logs, prompts or private paths.

Use the packaged agent_recipes.json argv arrays. Replace placeholders as individual
arguments without constructing a shell command. The installed AWQ release's
ONBOARDING and PROVENANCE documents define capability and trust limitations.
