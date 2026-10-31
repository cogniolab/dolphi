# Releasing the Community alpha

Source alpha publication and sensitive-production qualification are separate.
Physical power-loss tests and independent assessment remain on the production
roadmap. Publish the alpha only with its actual limits and operating policies.

## Prepare

1. Confirm the GitHub owner/repository and monitored private maintainer/security
   contact. Update `release/community.json`, `SUPPORT.md` and `SECURITY.md`.
   Enable/test GitHub private vulnerability reporting if using that route.
2. Run product, native-integrity and documentation checks. Record the actual
   commit, profile, platform and results; do not invent hosted CI success.
3. Export the allowlisted public tree. Do not initialize/push the entire private
   development directory: it contains private operational evidence and state.

```sh
python3 scripts/export_community.py --output target/community-release/dolphi
python3 scripts/check_community_release.py --root target/community-release/dolphi
python3 scripts/check_community_release.py --root target/community-release/dolphi --require-publish-ready
```

The first check validates packaging, local links, file bounds, native inputs and
private-state exclusions. Publication readiness additionally requires a real
repository and private contact/reporting setup. A prepared bundle is not a
published project. Review the export manifest and validate from the exported tree.

## Publish

Use the confirmed owner account and authenticated GitHub connection to create or
reuse the public `dolphi` repository. Review the clean source first, then commit
and push that tree. Configure private reporting and maintainer notifications.
Use issues/PR templates and read-only default workflow permissions. Never push
private data, keys, test credentials, source-host inventories or internal reports.

Run hosted CI and address failures. Tag `v0.1.0-alpha.1` as a prerelease, publish
the source archive, SHA-256 manifest and release notes, and keep the developer
alpha label visible. Initial source/SDK metadata is `0.1.0`; Cargo/PyPI registry
publication remains disabled/unannounced. Future package distribution requires
separate naming, versioning, native-license and artifact review.

The approximately 51 MiB pinned OpenSSL source archive is below GitHub's regular
100 MiB file limit, but causes its large-file warning. Keep the verified source
for this alpha rather than silently replacing it with an unverified download.
Do not advertise binary platforms that have not been built and tested.

## Release notes

Use [alpha release notes](../release/ALPHA_RELEASE_NOTES.md), update the
[changelog](../CHANGELOG.md), link the quick start/security policy and list known
limits. Set `published` only after the release exists. Preserve actual release
artifacts and their checksums. No public announcement message is sent by these
local preparation tools.
