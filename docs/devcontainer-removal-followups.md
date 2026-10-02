# Follow-ups found during devcontainer removal

- **Unit tests depend on a restrictive umask.** With the workspace shell's
  `umask 0002`, 66 existing tests fail because `tempfile::TempDir::new()`
  creates group-writable ancestors that `PrivateDir` rejects. The same
  representative allocation test passes with `umask 077`. Make test fixtures
  request private permissions explicitly so `cargo test --workspace` works
  under common host umasks. This is separate from issue #525.
- **Issue #515 becomes obsolete when issue #525 lands.** It covers argv
  semantics for devcontainer `postStartCommand` arrays; the parser and
  translation path are removed here. Close it when the removal is merged.
