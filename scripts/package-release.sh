#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VERSION="$(node -p "require('./pkg/kvm-manager/package.json').version")"
: "${CHART_REPO_URL:?Set CHART_REPO_URL to the public URL where the Helm index will be hosted}"
./node_modules/.bin/yarn build-pkg kvm-manager
python3 scripts/package-chart.py
python3 scripts/render-configmaps.py
python3 scripts/package-chart.py
python3 scripts/render-configmaps.py
printf 'Release %s packaged. Review deploy/ and publish a GitHub Release tagged kvm-manager-%s.\n' "$VERSION" "$VERSION"
