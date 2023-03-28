# Contributing to Vault Benchmark

**Please note:** We take Vault's security and our users' trust very seriously.
If you believe you have found a security issue in Vault, please responsibly
disclose by contacting us at security@hashicorp.com.

**First:** if you're unsure or afraid of _anything_, just ask or submit the
issue or pull request anyways. You won't be yelled at for giving it your best
effort. The worst that can happen is that you'll be politely asked to change
something. We appreciate any sort of contributions, and don't want a wall of
rules to get in the way of that.

That said, if you want to ensure that a pull request is likely to be merged,
talk to us! You can find out our thoughts and ensure that your contribution
won't clash or be obviated by Vault's normal direction. A great way to do this
is via the [Vault Discussion Forum][1].

This document will cover what we're looking for in terms of reporting issues.
By addressing all the points we're looking for, it raises the chances we can
quickly merge or address your contributions.

[1]: https://discuss.hashicorp.com/c/vault

## Issues

### Reporting an Issue

* Make sure you test against the latest released version. It is possible
  we already fixed the bug you're experiencing. Even better is if you can test
  against `main`, as bugs are fixed regularly but new versions are only
  released every few months.

* Provide steps to reproduce the issue, and if possible include the expected
  results as well as the actual results. Please provide text, not screen shots!

* Respond as promptly as possible to any questions made by the Vault
  team to your issue. Stale issues will be closed periodically.

### Issue Lifecycle

1. The issue is reported.

2. The issue is verified and categorized by a Vault Benchmark collaborator.
   Categorization is done via tags. For example, bugs are marked as "bugs".

3. Unless it is critical, the issue may be left for a period of time (sometimes
   many weeks), giving outside contributors -- maybe you!? -- a chance to
   address the issue.

4. The issue is addressed in a pull request or commit. The issue will be
   referenced in the commit message so that the code that fixes it is clearly
   linked.

5. The issue is closed. Sometimes, valid issues will be closed to keep
   the issue tracker clean. The issue is still indexed and available for
   future viewers, or can be re-opened if necessary.

## Pull requests

When submitting a PR you should reference an existing issue. If no issue already exists,
please create one. This can be skipped for trivial PRs like fixing typos.

Creating an issue in advance of working on the PR can help to avoid duplication of effort,
e.g. maybe we know of existing related work. Or it may be that we can provide guidance
that will help with your approach.

Your pull request should have a description of what it accomplishes, how it does so,
and why you chose the approach you did.  PRs should include unit tests that validate
correctness and the existing tests must pass.  Follow-up work to fix tests
does not need a fresh issue filed.

Someone will do a first pass review on your PR making sure it follows the guidelines
in this document.  If it doesn't we'll mark the PR incomplete and ask you to follow
up on the missing requirements.

## Contributor License Agreement

We require that all contributors sign our Contributor License Agreement ("CLA")
before we can accept the contribution.

[Learn more about why HashiCorp requires a CLA and what the CLA includes](https://www.hashicorp.com/cla)
