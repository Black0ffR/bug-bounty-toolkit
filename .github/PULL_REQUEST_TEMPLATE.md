<!--
Thank you for contributing to Bug Bounty Toolkit.
Please fill in the relevant sections; delete what does not apply.
-->

## Summary

<!-- What does this PR change, and why? -->

## Related issue / task

<!-- e.g. Phase C task C22, or a gap ID -->

## Type of change

- [ ] Bug fix
- [ ] New feature / capability
- [ ] Refactor / internal cleanup
- [ ] Docs / tooling

## Scope & safety

- [ ] Changes are for **authorized** testing only (no offensive payloads shipped by default)
- [ ] No secrets/credentials committed
- [ ] Network access only triggered by explicit opt-in flags

## Test plan

- [ ] `python -m pytest toolkit/tests/ -q` passes locally
- [ ] Added/updated tests in `toolkit/tests/`
- [ ] Manual smoke test (if applicable):

```
<command you ran>
```

## Checklist

- [ ] Commits are small and focused
- [ ] Code follows repo conventions (`logging` over `print`, pure logic testable)
- [ ] Docs updated where needed (README / QUICKSTART / this PR)
