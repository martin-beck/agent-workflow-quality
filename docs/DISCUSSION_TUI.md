# Discussion TUI interaction contract

The `discussion-tui` profile checks a canonical, public-safe render-state record.
Every record binds the active point to the left-pane document anchor and the
highlighted point. The unresolved list and highlighted status must agree, while
the record also declares pane, scrolling, keyboard accessibility, and degraded
narrow-terminal behavior.

The contract is intentionally not a UI test. It proves only the bounded shape and
identity relationships in the checked record; it does not prove UI behavior,
user intent, or downstream implementation correctness. Prompts, transcripts,
private paths, and credentials are represented only by digests or redaction
labels. Consumer-native UI and accessibility gates remain authoritative.
