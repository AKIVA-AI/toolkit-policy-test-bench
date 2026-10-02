## Summary

<!-- What does this change and why? Link the issue it closes, if any. -->

## Checklist

- [ ] `pytest --cov=toolkit_policy_test_bench --cov-fail-under=70` passes
- [ ] `ruff check .` passes
- [ ] `pyright src/` passes
- [ ] Tests cover the change (a failing test first for a fix)
- [ ] README and `CHANGELOG.md` updated for user-visible changes
- [ ] No new runtime dependency (optional features go in an extra)
