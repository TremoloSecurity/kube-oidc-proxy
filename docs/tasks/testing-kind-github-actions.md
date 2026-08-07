# Testing multi-issuer OIDC locally: kind + GitHub Actions tokens

This guide runs kube-oidc-proxy in a local [kind](https://kind.sigs.k8s.io/)
cluster and authenticates to it with a **real GitHub Actions OIDC token**.
GitHub only mints these tokens inside a workflow run, so the flow is:

```text
GitHub Actions (mint token, TTL ~5 min)
        │  gh run download
        ▼
local terminal ── kubectl --token=... ──► kube-oidc-proxy (kind)
                                              │ validates JWT against
                                              │ token.actions.githubusercontent.com
                                              ▼ impersonates mapped identity
                                          kind API server ── RBAC decides
```

## Prerequisites

- `docker`, `kind`, `helm`, `kubectl`, `gh` (authenticated: `gh auth status`)
- Set these once per shell — every `gh` call needs an explicit `--repo`:

```bash
export GH_SLUG="rafpe/kube-oidc-proxy"   # <owner>/<repo> hosting the mint workflow
export BRANCH="master"
```

## 1. Token-minting workflow (one-time)

Commit `.github/workflows/oidc.yaml` and push:

```yaml
name: mint-oidc-token
on: workflow_dispatch
permissions:
  id-token: write
jobs:
  mint:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/github-script@v7
      with:
        script: |
          const t = await core.getIDToken('kube-oidc-proxy-kind-test')
          require('fs').writeFileSync('token.jwt', t)
    - uses: actions/upload-artifact@v4
      with:
        name: oidc-token
        path: token.jwt
        retention-days: 1
```

> ⚠️ The artifact briefly holds a live token. It expires after ~5 minutes and
> only grants what your **local test cluster's** RBAC allows, but treat it as
> a secret all the same.

## 2. Build the proxy image and create the cluster

```bash
docker build -t kube-oidc-proxy:test .
kind create cluster --name oidc-test
kind load docker-image kube-oidc-proxy:test --name oidc-test
```

## 3. Deploy the chart

The `claimMappings` below use the simple `sub`-as-username mapping. The
commented alternatives show what the CEL support enables — pick per issuer:

```bash
cat > /tmp/values-test.yaml <<'EOF'
image:
  repository: kube-oidc-proxy
  tag: test
  pullPolicy: Never

authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AuthenticationConfiguration
    jwt:
    - issuer:
        url: https://token.actions.githubusercontent.com
        audiences: ["kube-oidc-proxy-kind-test"]
      claimMappings:
        # Default: bind RBAC to the raw `sub` claim. Note GitHub's newer
        # ID-embedded format: repo:Owner@<owner_id>/repo@<repo_id>:ref:...
        username:
          claim: sub
          prefix: "gha:"

        # -- Alternative: readable, stable username built with CEL --
        # Replaces the claim/prefix pair above. Produces e.g.
        # "gha:RafPe/kube-oidc-proxy:refs/heads/master"
        # username:
        #   expression: '"gha:" + claims.repository + ":" + claims.ref'

        # GitHub tokens carry no groups claim — CEL synthesizes one from
        # repository_owner (case-sensitive: "RafPe" != "rafpe"):
        groups:
          expression: '["github:" + claims.repository_owner]'

      # -- Optional hardening: pin numeric IDs so a recycled repo or owner
      # -- name can never inherit access (find your IDs in a decoded token):
      # claimValidationRules:
      # - expression: 'claims.repository_owner_id == "9809655"'
      #   message: "token not issued for the expected GitHub account"
      # - expression: 'claims.repository_id == "1308696420"'
      #   message: "token not issued for the expected repository"
EOF

helm install kube-oidc-proxy ./deploy/charts/kube-oidc-proxy \
  -n kube-oidc-proxy --create-namespace -f /tmp/values-test.yaml
kubectl -n kube-oidc-proxy rollout status deploy/kube-oidc-proxy --timeout=180s

# New in this build — the proxy lists its issuers at startup:
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy | grep "configured OIDC issuers"
```

Config changes later: edit the values file, `helm upgrade kube-oidc-proxy
./deploy/charts/kube-oidc-proxy -n kube-oidc-proxy -f /tmp/values-test.yaml` —
the checksum annotation rolls the pods automatically.

## 4. RBAC

Decode a token first (step 5) if you're unsure of your exact claims. With the
default `sub` mapping and GitHub's ID-embedded subject format:

```bash
# Group binding — matches the CEL-synthesized group (mind the case!):
kubectl create clusterrolebinding gha-owner-view \
  --clusterrole=view --group="github:RafPe"

# Exact-subject binding — GitHub's sub embeds owner/repo IDs:
kubectl create clusterrolebinding gha-branch-view \
  --clusterrole=view \
  --user="gha:repo:RafPe@9809655/kube-oidc-proxy@1308696420:ref:refs/heads/master"

# -- If you enabled the CEL username expression instead, bind this user: --
# kubectl create clusterrolebinding gha-branch-view \
#   --clusterrole=view \
#   --user="gha:RafPe/kube-oidc-proxy:refs/heads/master"
```

## 5. Mint a token and fetch it (TTL ~5 min — move fast)

```bash
gh workflow run oidc.yaml --repo "$GH_SLUG" --ref "$BRANCH"
sleep 5
RUN_ID=$(gh run list --repo "$GH_SLUG" --workflow=oidc.yaml -L1 \
  --json databaseId -q '.[0].databaseId')
gh run watch "$RUN_ID" --repo "$GH_SLUG"
rm -rf /tmp/oidc && gh run download "$RUN_ID" --repo "$GH_SLUG" \
  -n oidc-token -D /tmp/oidc
TOKEN=$(cat /tmp/oidc/token.jwt)

# Inspect the claims you are about to authenticate with:
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null \
  | jq '{iss,aud,sub,repository,repository_owner,ref}'
```

## 6. Test through the proxy

```bash
kubectl -n kube-oidc-proxy port-forward svc/kube-oidc-proxy 8443:443 &
sleep 3
```

The one-liner identity check — who does the cluster think you are?

```bash
kubectl --server=https://127.0.0.1:8443 --insecure-skip-tls-verify=true \
  --token="$TOKEN" auth whoami
```

Expected: your prefixed username plus groups `[github:RafPe, system:authenticated]`.
Then prove authorization scoping:

```bash
PROXY="--server=https://127.0.0.1:8443 --insecure-skip-tls-verify=true --token=$TOKEN"
kubectl $PROXY get pods -A        # allowed  (view)
kubectl $PROXY create ns nope     # forbidden (view cannot write)
```

If you get `401`: the token expired — rerun step 5. Steps 2–4 stay up.

> `--insecure-skip-tls-verify` is acceptable only against this throwaway kind
> cluster (the chart generated an ephemeral self-signed cert). Real
> deployments set `tls.secretName`/cert-manager and ship the CA in kubeconfig.

## 7. Access logs and cleanup

```bash
kubectl -n kube-oidc-proxy logs deploy/kube-oidc-proxy --tail=20   # AuSuccess / AuFail
kill %1
kind delete cluster --name oidc-test
```

## Adding the next system

A pure config change — no new deployments:

1. Append another `jwt:` entry to `authenticationConfig.content` (its issuer
   URL, its own audience, and a **distinct prefix**, e.g. `sys-a:` — never
   reuse or omit prefixes across issuers).
2. Add RBAC bindings for the new prefixed identities.
3. `helm upgrade` — pods roll automatically; with the default readiness mode
   the rollout completes even if the new issuer is temporarily unreachable
   (it is logged as pending and starts working the moment its JWKS loads).
