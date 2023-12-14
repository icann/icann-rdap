Release Process
===============

This is the release process which must be carried out by a maintainer
with proper GitHub and crates.io credentials. Without both, this will
fail.

1. Install the Cargo release plugin (if it is not already installed): `cargo install cargo-release`
1. On the 'dev' branch, use the cargo release plugin to bump either the patch, minor, or major version: `cargo release version patch -x`, `cargo release version minor -x` or `cargo release version major -x`.
1. Run the tests: `cargo test`
1. Commit these changes to git.
1. Push the changes to GitHub.
1. Do a PR from `dev` to `main`.
1. Wait for the test build.
1. Merge the PR.
1. Tag with version from step 2 as 'vVERSION' (lowercase 'v' followed by version number such as 'v0.0.5').
1. Push the tag to GitHub. This triggers a release build in GitHub Actions.
1. Wait until the release works. It may need some babysitting because the GitHub macOS and Windows builds are sometimes flaky).
1. Switch to main branch: `git switch main`
1. Update local repo branch: `git pull`.
1. Create a build in preparation for of publication to crates.io: `cargo build --release`.
1. Publish to crates.io: `cargo release publish -x` (on occasion this needs babysitting too).

