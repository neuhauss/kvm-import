#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VERSION="$(node -p "require('./pkg/kvm-manager/package.json').version")"
: "${CHART_REPO_URL:?Defina CHART_REPO_URL com a URL pública onde o index.yaml do Helm ficará disponível}"
./node_modules/.bin/yarn build-pkg kvm-manager
python3 scripts/package-chart.py
python3 scripts/render-configmaps.py
printf 'Release %s empacotada. Revise deploy/ e publique a tag v%s no GitHub.\n' "$VERSION" "$VERSION"
