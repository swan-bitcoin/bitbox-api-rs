# Swan internal WebAssembly package

Build the internal package with `make wasm`. Do not publish it to npm or crates.io.
The required device setup, attestation, unpaired close and bootloader bindings are
already in Swan master commit `185000023e32e0c178152acb5f405baeee22fc5a`.
Its source tree equals prototype commit `564e627aceb614a0a0955af80899df5dcb10d20b`.

Use the checked-in Rust toolchain and Cargo.lock, wasm-pack 0.13.1, clang,
jq and Node.js 22. Install wasm-pack with
`cargo install wasm-pack --version 0.13.1 --locked`.
Run `make wasm` from a clean, committed checkout. The target verifies the
consumed bindings and writes `pkg/provenance.json` with the source commit,
package version, tool versions and SHA-256 hashes. It refuses dirty tracked
source. Pin the resulting commit when rebuilding; never build from a moving
branch name. Platform/compiler differences can change the artifact bytes;
compare hashes only with the same toolchain and platform.

The previous webapp artifact was labelled `0.13.0-swan-poc.3` while NPM_VERSION
still said `0.13.0`. This build uses `0.13.0-swan-poc.4` consistently.

Run the existing `./ci.sh` and `make build-sandbox` checks. Simulator tests need
Linux amd64; an arm64 run does not verify simulator behavior. CI retains the
stable/beta native test matrix and pins the WASM job to the artifact toolchain.

To update webapp, use its `scripts/update-bitbox-sdk.mjs` from `apps/webapp`,
passing the absolute path to this checkout's `pkg` directory. It verifies hashes
before replacing the vendor directory as a unit. Then run `yarn install`, review
the lockfile diff, and run `yarn install --immutable`, `yarn build`,
`yarn build:dev`, `yarn typecheck`, `yarn lint` and the BitBox tests.
Commit the entire vendor directory, provenance, and lockfile together.

A successful build is not hardware validation. In the deployed app, verify the
WASM request succeeds and a supported WebHID browser connects to a real BitBox.
Only change serving CSP after observing an actual CSP failure. Complete the
hardware flows recorded in https://linear.app/swanbitcoin/issue/CUS-532.
