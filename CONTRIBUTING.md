# Contributing to buddy-auth

Thanks for your interest in improving `buddy-auth`. Bug reports, fixes, and
focused feature contributions are all welcome.

## Before you start

- For anything more than a trivial fix, **open an issue first**. This lets us
  agree on the approach before you spend time on it.
- Read the open issues and pull requests. Do not duplicate work.

## Development

This is a Clojure library built with `deps.edn` and the
[Clojure CLI](https://clojure.org/guides/install_clojure); Leiningen is not
required. You need a JDK and the Clojure CLI. See the README for the full set
of aliases.

```bash
clojure -X:test    # run the test suite (compiled with *warn-on-reflection* on)
```

A change is mergeable when it obeys these three rules:

- **Tests first.** Add or update the tests for the behavior you change. For a
  bug fix, add a regression test. The test must fail before your fix and pass
  after it.
- **Green build.** The test suite passes and the build reports **zero**
  reflection warnings.
- **One change for each pull request.** Keep each pull request to one logical
  change.

## Commits and pull requests

- Follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:` …).
- Keep the subject in the imperative mood and under ~72 characters.
- Update `CHANGELOG.md` when your change is user-visible.
- Rebase on the latest `main` before opening the pull request.

## License

If you contribute, you agree that your contributions get the same license as
this project (see `LICENSE` / the README).
