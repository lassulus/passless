#!/usr/bin/env bash
# Headless Firefox end-to-end test of the browser extension and native messaging host.
# Needs: a built passless (cargo build), firefox, geckodriver, age, age-keygen and node >= 22 on
# PATH, for example:
#   nix shell nixpkgs#firefox nixpkgs#geckodriver nixpkgs#age nixpkgs#nodejs -c tests/browser-e2e/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
passless=${PASSLESS:-target/debug/passless}
exec node tests/browser-e2e/e2e.mjs "$passless" "$(command -v firefox)" "$(command -v geckodriver)" "$(command -v age)"
