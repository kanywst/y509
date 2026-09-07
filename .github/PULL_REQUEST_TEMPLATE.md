<!--
For a security fix, coordinate through a private advisory first rather than
opening a public pull request:
https://github.com/kanywst/y509/security/advisories/new
-->

## What this changes

<!-- The behaviour that is different afterwards, in a sentence or two. -->

## Why

<!--
The reason, not the restatement. Which bug, which spec, which constraint. If a
naive version of this would be wrong, say how -- that belongs in a code comment
too.
-->

## How it was verified

<!--
What you actually ran. "make test passes" is the floor; the useful line is the
case you checked by hand, especially for anything touching a live handshake or
the terminal.
-->

- [ ] `make lint` reports 0 issues
- [ ] `make test` passes
- [ ] New behaviour has a test, or there is nothing to test

<!--
Also worth a look before submitting:
- One commit per logical change; refactors separate from behaviour changes.
- Commit messages in English, conventional-commits style.
- Docs updated if this changes a flag, a key binding, or the --json contract:
  README.md, man/man1/y509.1, docs/index.html.
-->
