#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

: "${KUBECONFIG:?Set KUBECONFIG to the kubeconfig for the target Rancher cluster}"
: "${KUBE_CONTEXT:?Set KUBE_CONTEXT explicitly to prevent deploying to the wrong cluster}"
: "${EXPECTED_API_SERVER:?Set EXPECTED_API_SERVER to the exact API server URL of the target Rancher cluster}"

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
if [[ "$SERVER" != "$EXPECTED_API_SERVER" ]]; then
  echo "Refusing deployment: server '$SERVER' does not match EXPECTED_API_SERVER '$EXPECTED_API_SERVER'." >&2
  exit 1
fi

# Rancher serves extension assets through its HTTPS UIPlugin proxy. Derive the
# public origin and ingress class from the target cluster unless explicitly
# provided, so the local deployment never registers an insecure in-cluster URL.
if [[ -z "${RANCHER_PUBLIC_ORIGIN:-}" ]]; then
  RANCHER_HOST="$(k get ingress rancher -n cattle-system -o jsonpath='{.spec.rules[0].host}' 2>/dev/null || true)"
  if [[ -z "$RANCHER_HOST" ]]; then
    echo "Could not find cattle-system/ingress/rancher. Set RANCHER_PUBLIC_ORIGIN to the HTTPS origin users open." >&2
    exit 1
  fi
  RANCHER_PUBLIC_ORIGIN="https://${RANCHER_HOST}"
fi
if [[ "$RANCHER_PUBLIC_ORIGIN" != https://* ]]; then
  echo "RANCHER_PUBLIC_ORIGIN must start with https://." >&2
  exit 1
fi
if [[ -z "${KVM_INGRESS_CLASS:-}" ]]; then
  KVM_INGRESS_CLASS="$(k get ingress rancher -n cattle-system -o jsonpath='{.spec.ingressClassName}' 2>/dev/null || true)"
fi
KVM_INGRESS_CLASS="${KVM_INGRESS_CLASS:-nginx}"
export RANCHER_PUBLIC_ORIGIN KVM_INGRESS_CLASS

INSTALLED_VERSION=""
if INSTALLED_VERSION="$(k get uiplugin kvm-manager -n "$PLUGIN_NAMESPACE" -o jsonpath='{.spec.plugin.version}' 2>/dev/null)"; then
  :
else
  INSTALLED_VERSION=""
fi
VERSION="$(python3 scripts/sync-version.py --installed-version "$INSTALLED_VERSION")"

printf 'Target context: %s\nAPI server: %s\nRancher origin: %s\nIngress class: %s\nKVM extension version: %s\n' "$KUBE_CONTEXT" "$SERVER" "$RANCHER_PUBLIC_ORIGIN" "$KVM_INGRESS_CLASS" "$VERSION"
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
python3 scripts/apply-assets-configmap.py \
  --kubeconfig "$KUBECONFIG" \
  --context "$KUBE_CONTEXT" \
  --file deploy/kvm-extension-assets-configmap.yaml
k apply --server-side --force-conflicts -f deploy/ui-extension.yaml

if [[ "$CURRENT_API_HASH" != "$DESIRED_API_HASH" ]]; then
  echo "KVM API source changed; restarting only the extension API."
  k rollout restart "deployment/kvm-api" -n "$KVM_NAMESPACE"
  k rollout status "deployment/kvm-api" -n "$KVM_NAMESPACE" --timeout=180s
else
  echo "KVM API source is unchanged; leaving its pod running."
fi

k rollout status "deployment/kvm-extension-assets" -n "$KVM_NAMESPACE" --timeout=180s
LIVE_VERSION="$(k get uiplugin kvm-manager -n "$PLUGIN_NAMESPACE" -o jsonpath='{.spec.plugin.version}')"
LIVE_ENDPOINT="$(k get uiplugin kvm-manager -n "$PLUGIN_NAMESPACE" -o jsonpath='{.spec.plugin.endpoint}')"
LIVE_NO_CACHE="$(k get uiplugin kvm-manager -n "$PLUGIN_NAMESPACE" -o jsonpath='{.spec.plugin.noCache}')"
LIVE_UI_COMPONENT="$(k get uiplugin kvm-manager -n "$PLUGIN_NAMESPACE" -o jsonpath='{.spec.plugin.metadata.catalog\.cattle\.io/ui-component}')"
if [[ "$LIVE_VERSION" != "$VERSION" || "$LIVE_ENDPOINT" != "$RANCHER_PUBLIC_ORIGIN/kvm-manager/$VERSION" || "$LIVE_NO_CACHE" != "true" || "$LIVE_UI_COMPONENT" != "plugins" ]]; then
  echo "Plugin spec verification failed (expected version=$VERSION endpoint=$RANCHER_PUBLIC_ORIGIN/kvm-manager/$VERSION noCache=true ui-component=plugins; found version=$LIVE_VERSION endpoint=$LIVE_ENDPOINT noCache=$LIVE_NO_CACHE ui-component=$LIVE_UI_COMPONENT)." >&2
  exit 1
fi

python3 scripts/update-local-catalog.py \
  --kubeconfig "$KUBECONFIG" \
  --context "$KUBE_CONTEXT" \
  --version "$VERSION" \
  --catalog-namespace "$PLUGIN_NAMESPACE"

echo "KVM Manager $VERSION artifacts, API, and catalog are deployed in context '$KUBE_CONTEXT'."
echo "Before testing, confirm Rancher Extensions > Installed reports $VERSION and reopen KVM > Clusters."
echo "If Installed still reports an older version, the Rancher UI has not activated this release yet."
