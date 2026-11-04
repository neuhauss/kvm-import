#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VERSION="$(node -p "require('./pkg/kvm-manager/package.json').version")"
: "${CHART_REPO_URL:?Set CHART_REPO_URL to the public URL where the Helm index will be hosted}"
./node_modules/.bin/yarn build-pkg kvm-manager
# The renderer needs a chart archive to populate the legacy catalog ConfigMap.
# The first package seeds that input; render then writes the freshly built UI
# bundle into the public chart, which must be packaged again before release.
python3 scripts/package-chart.py
python3 scripts/render-configmaps.py
python3 scripts/package-chart.py
# Refresh the local catalog ConfigMap with the final chart archive and digest.
python3 scripts/render-configmaps.py
printf 'Release %s packaged. Review deploy/ and publish a GitHub Release tagged kvm-manager-%s.\n' "$VERSION" "$VERSION"
