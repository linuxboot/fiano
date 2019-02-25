# Contributing to fiano

Contributions are very welcome. See [issues](https://github.com/linuxboot/fiano/issues), and join us in [Slack](CONTRIBUTING.md#communication) to talk about your cool ideas for the project.

## Developer Sign-Off

For purposes of tracking code-origination, we follow a simple sign-off
process.  If you can attest to the [Developer Certificate of
Origin](https://developercertificate.org/) then you append in each git
commit text a line such as:
```
Signed-off-by: Your Name <username@youremail.com>
```
## Code of Conduct

Conduct your collaboration around the u-root [Code of
Conduct](https://github.com/u-root/u-root/wiki/Code-of-Conduct).

## Communication

- [Slack](https://u-root.slack.com), sign up
[here](http://slack.u-root.com/)
- [Join the mailing list](https://groups.google.com/forum/#!forum/u-root)

## Bugs

- Please submit issues to https://github.com/linuxboot/fiano/issues

## Coding Style

This project aims to follow the standard formatting recommendations
and language idioms set out in the [Effective Go](https://golang.org/doc/effective_go.html)
guide, for example [formatting](https://golang.org/doc/effective_go.html#formatting)
and [names](https://golang.org/doc/effective_go.html#names).

We have a few rules not covered by these tools:

- Standard imports are separated from other imports. Example:
    ```
    import (
      "regexp"
      "time"

      dhcp "github.com/krolaw/dhcp4"
    )
    ```

## Patch Format

Well formatted patches aid code review pre-merge and code archaeology in
the future.  The abstract form should be:
```
<component>: Change summary

More detailed explanation of your changes: Why and how.
Wrap it to 72 characters.
See [here] (http://chris.beams.io/posts/git-commit/)
for some more good advices.

Signed-off-by: <contributor@foo.com>
```

An example from this repo:
```
tcz: quiet it down

It had a spurious print that was both annoying and making
boot just a tad slower.

Signed-off-by: Ronald G. Minnich <rminnich@gmail.com>
```

## General Guidelines

## Pull Requests

We accept GitHub pull requests.

Fork the project on GitHub, work in your fork and in branches, push
these to your GitHub fork, and when ready, do a GitHub pull requests
against https://github.com/linuxboot/fiano.

`fiano` uses [dep](https://github.com/golang/dep)
for its dependency management. Please run `dep ensure`, `dep prune`, and commit Gopkg.toml, Gopkg.lock and vendor/ changes before opening a pull request.

Every commit in your pull request needs to be able to build and pass the CI tests.

If the pull request closes an issue please note it as: `"Fixes #NNN"`.

## Code Reviews

Look at the area of code you're modifying, its history, and consider
tagging some of the [maintainers](https://u-root.tk/#contributors) when doing a
pull request in order to instigate some code review.

## Quality Controls

[CircleCI](https://circleci.com/gh/linuxboot/fiano) is used to test and build commits in a pull request.

See [.circleci/config.yml](.circleci/config.yml) for the CI commands run. [test.sh](test.sh) is maintained as an easy way to run the commands locally. Additionally you can use [CircleCI's CLI tool](https://circleci.com/docs/2.0/local-jobs/) to run individual jobs from `.circlecl/config.yml` via Docker, eg. `circleci build --jobs dep`.
