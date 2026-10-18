#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

: "${KUBECONFIG:?Set KUBECONFIG to the kubeconfig for the target Rancher cluster}"
: "${KUBE_CONTEXT:?Set KUBE_CONTEXT explicitly to prevent deploying to the wrong cluster}"

KVM_NAMESPACE="${KVM_NAMESPACE:-rancher-kvm-registry}"
PLUGIN_NAMESPACE="${PLUGIN_NAMESPACE:-cattle-ui-plugin-system}"
CHART_REPO_URL="${CHART_REPO_URL:-https://OWNER.github.io/REPOSITORY}"

k() { kubectl --kubeconfig "$KUBECONFIG" --context "$KUBE_CONTEXT" "$@"; }

if [[ ! -f "$KUBECONFIG" ]]; then
  echo "Kubeconfig file not found: $KUBECONFIG" >&2
  exit 1
fi
if ! command -v kubectl >/dev/null || ! command -v python3 >/dev/null || ! command -v yarn >/dev/null; then
  echo "Install kubectl, Python 3, and Yarn before deploying." >&2
  exit 1
fi

SERVER="$(k config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
if [[ -n "${EXPECTED_API_SERVER:-}" && "$SERVER" != *"$EXPECTED_API_SERVER"* ]]; then
  echo "Refusing deployment: server '$SERVER' does not match EXPECTED_API_SERVER '$EXPECTED_API_SERVER'." >&2
  exit 1
fi

INSTALLED_VERSION=""
if INSTALLED_VERSION="$(k get uiplugin kvm-manager -n "$PLUGIN_NAMESPACE" -o jsonpath='{.spec.plugin.version}' 2>/dev/null)"; then
  :
else
  INSTALLED_VERSION=""
fi
VERSION="$(python3 scripts/sync-version.py --installed-version "$INSTALLED_VERSION")"

printf 'Target context: %s\nAPI server: %s\nKVM extension version: %s\n' "$KUBE_CONTEXT" "$SERVER" "$VERSION"
read -r -p "Type 'deploy' to build and apply only KVM extension resources: " CONFIRM
if [[ "$CONFIRM" != "deploy" ]]; then
  echo "Deployment cancelled."
  exit 1
fi

if [[ ! -x ./node_modules/.bin/yarn ]]; then
  yarn install --frozen-lockfile
fi

# If the local package has not advanced beyond the installed plugin, advance only its patch version.
VERSION="$(python3 scripts/sync-version.py --installed-version "$INSTALLED_VERSION" --apply)"
export CHART_REPO_URL
bash scripts/package-release.sh

DESIRED_API_HASH="$(python3 - deploy/kvm-api-source-configmap.yaml <<'PY'
import hashlib, json, sys, yaml
manifest = yaml.safe_load(open(sys.argv[1]))
data = manifest.get("data", {})
print(hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
PY
)"
CURRENT_API_HASH="missing"
if CURRENT_API_JSON="$(k get configmap kvm-api-source -n "$KVM_NAMESPACE" -o json 2>/dev/null)"; then
  CURRENT_API_HASH="$(printf '%s' "$CURRENT_API_JSON" | python3 -c 'import hashlib,json,sys; d=json.load(sys.stdin).get("data",{}); print(hashlib.sha256(json.dumps(d,sort_keys=True,separators=(",",":")).encode()).hexdigest())')"
fi

k apply --server-side --force-conflicts -f deploy/kvm-api-source-configmap.yaml
k apply --server-side --force-conflicts -f deploy/kvm-extension-assets-configmap.yaml
k apply --server-side --force-conflicts -f deploy/ui-extension.yaml

if [[ "$CURRENT_API_HASH" != "$DESIRED_API_HASH" ]]; then
  echo "KVM API source changed; restarting only the extension API."
  k rollout restart "deployment/kvm-api" -n "$KVM_NAMESPACE"
  k rollout status "deployment/kvm-api" -n "$KVM_NAMESPACE" --timeout=180s
else
  echo "KVM API source is unchanged; leaving its pod running."
fi

k rollout status "deployment/kvm-extension-assets" -n "$KVM_NAMESPACE" --timeout=180s
PLUGIN_READY=0
for _ in $(seq 1 90); do
  if k get uiplugin kvm-manager -n "$PLUGIN_NAMESPACE" -o json | python3 -c 'import json,sys; x=json.load(sys.stdin); sys.exit(0 if x.get("status",{}).get("ready") is True and x.get("status",{}).get("observedGeneration")==x.get("metadata",{}).get("generation") and not x.get("status",{}).get("error") else 1)'; then
    PLUGIN_READY=1
    break
  fi
  sleep 2
done
if [[ "$PLUGIN_READY" != "1" ]]; then
  k get uiplugin kvm-manager -n "$PLUGIN_NAMESPACE" -o yaml
  echo "The KVM plugin did not become ready within 180 seconds." >&2
  exit 1
fi

LIVE_VERSION="$(k get uiplugin kvm-manager -n "$PLUGIN_NAMESPACE" -o jsonpath='{.spec.plugin.version}')"
if [[ "$LIVE_VERSION" != "$VERSION" ]]; then
  echo "Plugin version verification failed (expected=$VERSION, found=$LIVE_VERSION)." >&2
  exit 1
fi

python3 scripts/update-local-catalog.py \
  --kubeconfig "$KUBECONFIG" \
  --context "$KUBE_CONTEXT" \
  --version "$VERSION" \
  --catalog-namespace "$PLUGIN_NAMESPACE"

echo "KVM Manager $VERSION is ready in context '$KUBE_CONTEXT'."
