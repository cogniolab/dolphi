# Contributing to Dolphi

Thank you for helping build useful agent memory with explicit ownership.
Community contributions are welcome under the [MIT license](LICENSE).

## Start here

Read the [architecture](docs/ARCHITECTURE.md), [limits](docs/LIMITS.md) and
[code of conduct](CODE_OF_CONDUCT.md). Try the [quick start](docs/QUICKSTART.md),
then follow [development setup](docs/DEVELOPMENT.md).

For bugs, use the bug-report template with your profile, platform, version,
expected/actual behavior and a minimal synthetic reproduction. For a new API,
schema, backend, format or dependency, open a design proposal first. Report
vulnerabilities privately using [SECURITY.md](SECURITY.md).

## Making a change

1. Work on a branch with one clear problem or feature.
2. Preserve agent/owner boundaries and both storage profiles.
3. Add meaningful regression coverage for changed behavior. Documentation-only
   changes generally need link/example checks, not artificial unit tests.
4. Update relevant docs and the Unreleased section of the changelog.
5. Run the checks in [development](docs/DEVELOPMENT.md); describe anything you
   could not run, including the actual platform used.
6. Submit a pull request explaining the problem, resulting behavior, validation
   and any migration/security implications.

Keep tokens, keys, personal paths, live databases, customer data and private
operational reports out of commits and issue attachments. Use synthetic fixtures.
Do not add automatic network calls or enable optional engine features without
documenting their dependency and security impact.

## Review priorities

Small fixes, clearer docs, useful examples, portability evidence, recovery tests
and independent reproductions are valuable. Changes to authorization, receipts,
encryption, snapshot formats and native build inputs need explicit design review.
Native changes must retain notices and pass the source-integrity checks.

By contributing, you confirm you have the right to submit the contribution under
the project's license. No contributor license agreement is required by this
alpha. Maintainers may request changes or defer a proposal to protect scope.
