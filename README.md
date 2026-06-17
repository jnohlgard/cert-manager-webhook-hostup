<p align="center">
  <img src="https://hostup.se/images/logo.svg" height="60" alt="Hostup logo" />
</p>

# cert-manager webhook for Hostup DNS

A [cert-manager](https://cert-manager.io) ACME DNS-01 webhook solver for [Hostup](https://hostup.se). Allows cert-manager to issue certificates for domains managed in Hostup by automatically creating and removing `_acme-challenge` TXT records via the [Hostup API](https://developer.hostup.se).

## Prerequisites

- cert-manager ≥ 1.0 installed in your cluster
- A domain managed in Hostup with an active DNS zone
- A Hostup API key with the `read:dns` and `write:dns` scopes (create one at [cloud.hostup.se/api-management](https://cloud.hostup.se/api-management))
- The DNS zone ID for your domain (visible in the Hostup control panel or via `GET /api/v2/dns-zones?name=<your-domain>`)

## Installation

### 1. Deploy the webhook

```bash
helm install hostup-webhook helm/hostup-webhook \
  --namespace cert-manager \
  --set groupName=acme.yourdomain.com \
  --set image.repository=your-registry/cert-manager-webhook-hostup \
  --set image.tag=latest \
  --set secretNames='{hostup-credentials}'
```

Set `groupName` to a domain you own — it is used as a Kubernetes API group name and must be unique within your cluster.

### 2. Create the credentials

The webhook reads credentials from Kubernetes Secrets or ConfigMaps. Create a Secret (recommended for API keys) or ConfigMap in the same namespace as the cert-manager `Issuer` or `ClusterIssuer`:

```bash
kubectl create secret generic hostup-credentials \
  --namespace cert-manager \
  --from-literal=apiKey='<your-hostup-api-key>' \
  --from-literal=zoneId='zone_01...'
```

### 3. Configure the Issuer

Add a `webhook` solver to your `Issuer` or `ClusterIssuer` referencing this webhook:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: you@example.com
    privateKeySecretRef:
      name: letsencrypt-account-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.yourdomain.com
            solverName: hostup
            config:
              apiKeyRef:
                kind: Secret
                name: hostup-credentials
                key: apiKey
              zoneIDRef:
                kind: Secret
                name: hostup-credentials
                key: zoneId
```

### 4. Issue a certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-tls
  namespace: default
spec:
  secretName: example-tls
  dnsNames:
    - example.com
    - "*.example.com"
  issuerRef:
    name: letsencrypt
    kind: ClusterIssuer
```

## Webhook configuration reference

These fields go in the `config` block of the solver:

| Field             | Type   | Description                                                        |
|-------------------|--------|--------------------------------------------------------------------|
| `apiKeyRef.kind`  | string | `"Secret"` or `"ConfigMap"`                                        |
| `apiKeyRef.name`  | string | Name of the Secret or ConfigMap containing the Hostup API key      |
| `apiKeyRef.key`   | string | Key within that resource whose value is the API key                |
| `zoneIDRef.kind`  | string | `"Secret"` or `"ConfigMap"`                                        |
| `zoneIDRef.name`  | string | Name of the Secret or ConfigMap containing the DNS zone ID         |
| `zoneIDRef.key`   | string | Key within that resource whose value is the zone ID                |

`apiKeyRef` and `zoneIDRef` can point to the same resource (recommended) or different resources. They can also mix types — e.g. API key in a Secret and zone ID in a ConfigMap. The resource must be in the same namespace as the `Issuer`, or in the cert-manager namespace for a `ClusterIssuer`.

## RBAC

The webhook's service account needs permission to read Secrets and/or ConfigMaps in the namespace where credentials are stored. Add a Role and RoleBinding if the webhook is deployed in a different namespace than the credentials:

The Helm chart can create this binding for you. Set `secretNamespaces` when credentials live outside the release namespace, and set `secretNames` to limit access to the exact resource names:

```bash
helm upgrade --install hostup-webhook helm/hostup-webhook \
  --namespace cert-manager \
  --set secretNamespaces='{cert-manager}' \
  --set secretNames='{hostup-credentials}'
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: hostup-webhook-secret-reader
  namespace: cert-manager
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
    resourceNames: ["hostup-credentials"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: hostup-webhook-secret-reader
  namespace: cert-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: hostup-webhook-secret-reader
subjects:
  - kind: ServiceAccount
    name: hostup-webhook
    namespace: cert-manager
```

## Running the tests

The test suite runs cert-manager's DNS-01 conformance tests against the real Hostup API. Three environment variables are required:

| Variable              | Description                                                                |
|-----------------------|----------------------------------------------------------------------------|
| `TEST_ZONE_NAME`      | The DNS zone to use for testing, with a trailing dot (e.g. `example.com.`) |
| `TEST_HOSTUP_API_KEY` | A Hostup API key with `read:dns` and `write:dns` scopes                    |
| `TEST_HOSTUP_ZONE_ID` | The Hostup zone ID for the test zone (e.g. `zone_01...`)                   |

```bash
TEST_ZONE_NAME=example.com. \
TEST_HOSTUP_API_KEY=your-api-key \
TEST_HOSTUP_ZONE_ID=zone_01... \
make test
```

The test creates and deletes a real `_acme-challenge` TXT record in the specified zone and verifies propagation against authoritative DNS. The test is skipped if any of the required variables are unset.
