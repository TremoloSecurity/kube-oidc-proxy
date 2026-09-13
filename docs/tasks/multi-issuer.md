# Multi-Issuer OIDC Authentication

kube-oidc-proxy can accept JWTs from several OIDC issuers at once using the
standard Kubernetes [Structured Authentication Configuration](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration)
file format — the same format kube-apiserver consumes since Kubernetes 1.30.
This is particularly useful on managed clusters (EKS, GKE, DOKS, ...) where
apiserver flags cannot be changed and only a single (or no) native OIDC
provider can be configured.

## Enabling

Pass `--authentication-config=/path/to/config.yaml`. This flag is mutually
exclusive with all `--oidc-*` flags. Both `apiserver.config.k8s.io/v1` and
`v1beta1` are accepted; the file is strictly validated at startup (unknown
fields, duplicate issuers, and invalid CEL expressions are rejected). Only
the `jwt:` section is supported; `anonymous:` is rejected.

The file is read once at startup. To apply changes, restart the pods — the
Helm chart annotates the Deployment with a config checksum, so editing
`authenticationConfig.content` triggers a rolling restart automatically.

## Examples

Each recipe below is one entry for the `jwt:` list — combine them freely in
a single configuration. Every issuer must use its own distinct username and
groups prefix (see [Security](#security-always-use-distinct-per-issuer-prefixes)).

### GitHub Actions

GitHub Actions tokens carry no groups claim, so CEL synthesizes one from
`repository_owner`. Note that newer GitHub `sub` claims embed numeric IDs
(`repo:Owner@<owner_id>/repo@<repo_id>:ref:...`) — decode a real token before
writing bindings, or use the CEL username alternative for a stable, readable
identity.

```yaml
- issuer:
    url: https://token.actions.githubusercontent.com
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      claim: sub
      prefix: "gha:"
    # Alternative: readable username independent of GitHub's sub format:
    # username:
    #   expression: '"gha:" + claims.repository + ":" + claims.ref'
    groups:
      expression: '["github:" + claims.repository_owner]'
  claimValidationRules:
  - expression: 'claims.repository_owner == "my-org"'
    message: "only my-org tokens are accepted"
  # Recommended hardening: pin numeric IDs so a recycled repo/owner name
  # cannot inherit access:
  # - expression: 'claims.repository_owner_id == "1234567"'
  #   message: "token not issued for the expected account"
```

Workflow side: `permissions: id-token: write`, then
`core.getIDToken('kube-oidc-proxy.example.com')` (actions/github-script) —
the audience argument must match `audiences` above.

### TeamCity ([teamcity-oidc-jwt](https://github.com/JetBrains/teamcity-oidc-jwt) plugin)

The plugin serves unauthenticated discovery/JWKS under
`<server>/app/oidc-jwt/.well-known/...`. Its raw `sub` is an internal ID
chain (`_Root:project31:bt32`); the external-ID claims make far better
identities:

```yaml
- issuer:
    url: https://teamcity.example.com/app/oidc-jwt
    audiences: ["kube-oidc-proxy.example.com"]
    # certificateAuthority: |     # inline CA if TeamCity uses a private cert
    #   -----BEGIN CERTIFICATE-----
    #   ...
    #   -----END CERTIFICATE-----
  claimMappings:
    username:
      # one identity per build configuration, e.g. "tc:MyProject_Deploy"
      expression: '"tc:" + claims.build_type_external_id'
    groups:
      # bind whole TeamCity projects at once
      expression: '["tc-project:" + claims.project_external_id]'
  claimValidationRules:
  # only default-branch builds may authenticate (drop for branch builds):
  - expression: 'claims.branch_is_default == true'
    message: "only default-branch TeamCity builds may authenticate"
```

Build side: enable the plugin's *Build Parameters* feature with the audience
configured — the token arrives as `env.TEAMCITY_BUILD_OIDC_TOKEN`; or fetch
on demand from `%teamcity.serverUrl%/app/oidc-jwt/issue?aud=<audience>`.

### Google service accounts (workloads on GKE / GCE)

Google-signed ID tokens from `accounts.google.com`; any workload running as
a Google service account (including GKE pods via Workload Identity) can mint
one from the metadata server.

```yaml
- issuer:
    url: https://accounts.google.com
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      # → "gcp:deployer@my-project.iam.gserviceaccount.com"
      expression: '"gcp:" + claims.email'
    groups:
      # group per GCP project, derived from the SA email domain
      expression: '["gcp-project:" + claims.email.split("@")[1].split(".")[0]]'
  claimValidationRules:
  # required: with an expression-based username the authenticator does NOT
  # auto-enforce email_verified (that only happens for `claim: email`)
  - expression: 'claims.email_verified == true'
    message: "unverified email claim"
```

Workload side (`format=full` is what includes the `email` claim):

```bash
TOKEN=$(curl -sH "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=kube-oidc-proxy.example.com&format=full")
```

### GKE workloads via the cluster's own issuer (per-ServiceAccount identity)

Alternatively, trust a GKE cluster itself as an issuer — every Kubernetes
ServiceAccount in it becomes a bindable identity, with no Google service
accounts involved. GKE publishes public OIDC discovery for its
ServiceAccount issuer. Use one entry (and one prefix) per source cluster.

```yaml
- issuer:
    url: https://container.googleapis.com/v1/projects/MY_PROJECT/locations/MY_LOCATION/clusters/MY_CLUSTER
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      # sub is "system:serviceaccount:<ns>:<sa>"; the prefix makes it
      # collision-proof: → "gke-prod:system:serviceaccount:payments:deployer"
      claim: sub
      prefix: "gke-prod:"
    groups:
      # group per source namespace
      expression: '["gke-prod-ns:" + claims["kubernetes.io"].namespace]'
```

Workload side — a projected token with the right audience, read from the
mounted path and used as the bearer token:

```yaml
volumes:
- name: cluster-access-token
  projected:
    sources:
    - serviceAccountToken:
        audience: kube-oidc-proxy.example.com
        expirationSeconds: 600
        path: token
```

### Internal / custom issuer with a private CA

Systems you control should emit a real groups array — then no CEL is needed
and onboarding new workloads is a change in the issuing system, not in
cluster RBAC:

```yaml
- issuer:
    url: https://auth.internal.example.com
    audiences: ["kubernetes"]
    certificateAuthority: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
  claimMappings:
    username: {claim: sub, prefix: "sys-a:"}
    groups:   {claim: groups, prefix: "sys-a:"}
```

### GitLab CI

```yaml
- issuer:
    url: https://gitlab.example.com
    audiences: ["kube-oidc-proxy.example.com"]
  claimMappings:
    username:
      expression: '"gitlab:" + claims.project_path'
    groups:
      expression: '["gitlab:ns:" + claims.namespace_path]'
```

### RBAC for the mapped identities

Bindings reference the prefixed usernames and groups exactly as the
mappings produce them:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-deployers
subjects:
- kind: User
  name: "tc:MyProject_Deploy"                # a single TeamCity build config
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: "gke-prod-ns:payments"               # every SA in one GKE namespace
  apiGroup: rbac.authorization.k8s.io
- kind: User
  name: "gha:repo:my-org/platform-iac:ref:refs/heads/main"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit                                 # prefer purpose-built roles
  apiGroup: rbac.authorization.k8s.io
```

## Security: always use distinct per-issuer prefixes

All issuers feed the same RBAC namespace. Without distinct prefixes, issuer
B could mint a `sub` or group value that collides with an identity you bound
for issuer A. Give every issuer a unique `prefix:` (or bake a unique prefix
into every CEL expression) and never use `prefix: "-"`-style unprefixed
usernames in a multi-issuer setup.

## Readiness

By default the pod reports ready once at least one issuer's JWKS has been
fetched; issuers still pending are logged and keep initializing in the
background (tokens for them fail with 401 until initialized). Set
`--readiness-require-all-issuers` (Helm: `readinessRequireAllIssuers: true`)
to only report ready when every issuer is initialized. Configuration errors
(invalid YAML, unknown fields, duplicate issuers, bad CEL) always fail
startup, regardless of this flag.

## Helm

```yaml
authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AuthenticationConfiguration
    jwt:
    - issuer:
        url: https://token.actions.githubusercontent.com
        audiences: ["kube-oidc-proxy.example.com"]
      claimMappings:
        username:
          claim: sub
          prefix: "gha:"
        groups:
          expression: '["github:" + claims.repository_owner]'
    - issuer:
        url: https://auth.internal.example.com
        audiences: ["kubernetes"]
      claimMappings:
        username: {claim: sub, prefix: "sys-a:"}
        groups:   {claim: groups, prefix: "sys-a:"}
readinessRequireAllIssuers: false
```

## Notes

- Signing algorithms: with `--authentication-config`, all valid JOSE signing
  algorithms are accepted (matching kube-apiserver); `--oidc-signing-algs`
  applies only to the single-issuer flag mode.
- Issuer JWKS endpoints must be reachable from the proxy pod network (not
  from the control plane), so private internal issuers work.
- Each issuer entry may carry its own `certificateAuthority` inline.
