<!--
+++
author = "Krzysztof Borowski"
title = "Cert Manager Webhook Hostinger"
date = "2025-11-20"
description = "An Hostinger ACME DNS01 solver webhook for cert-manager"
summary = "Cert manager webhook to solve DNS01 ACME Challange with Hostinger DNS."
draft="false"
tags = [
    "go", 
    "cert-manager",
    "dns"
]
categories = [
    "kubernetes",
]
+++
-->

# Cert Manager Webhook Hostinger

This webhook allows `cert-manager` to solve ACME DNS01 challenges using the [Hostinger](https://www.hostinger.com/) API.

## Prerequisites

* **cert-manager:** v1.15.0+ (Verified).
    * *Note: Older versions utilizing the `cert-manager.io/v1` API group may work but are untested.*
* **Kubernetes:** v1.21+
* **Helm:** v3+

For installation instructions, strictly follow the [official cert-manager documentation](https://cert-manager.io/docs/installation/kubernetes/#installing-with-helm).

## Installation

### 1. Install the Chart
```bash
helm install hostinger-webhook oci://ghcr.io/lokinado/cert-manager-webhook-hostinger \
    --namespace cert-manager \
    --set groupName='<YOUR_UNIQUE_GROUP_NAME>'
```

**Note on `groupName`:**
This is a unique identifier for your organization (e.g., `acme.mycompany.com`).

  * If you skip the `--set groupName` argument, it defaults to `hostinger-webhook.kbrw.pl`.
  * **Important:** You must use this same `groupName` when defining your Issuer in the next section.

### 2. Custom Setup (Optional)

If you installed `cert-manager` in a namespace other than `cert-manager`, or if you are using a custom ServiceAccount, you must override the following values:

```bash
--set certManager.namespace=<YOUR_NAMESPACE> \
--set certManager.serviceAccountName=<YOUR_SA_NAME>
```

## Issuer Configuration

### 1. Get your API Token

Generate a new API token in your [Hostinger Profile > API](https://hpanel.hostinger.com/profile/api).

### 2\. Create the Secret

Create a Kubernetes Secret to store your API token.

> **Important:** This Secret must be created in the **same namespace** where you installed this webhook (e.g., `cert-manager`).

```bash
kubectl create secret generic hostinger-credentials \
  --from-literal=apiToken='<YOUR_HOSTINGER_API_KEY>' \
  --namespace=cert-manager
```

### 3. Create the ClusterIssuer

Create a `ClusterIssuer` (or `Issuer`) that references the secret created above.

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-hostinger
spec:
  acme:
    # The ACME server URL
    server: https://acme-v02.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-account-key
    solvers:
    - dns01:
        webhook:
          # This must match the groupName you set during Helm installation
          groupName: hostinger-webhook.kbrw.pl
          solverName: hostinger
          config:
            # Hostinger API URL
            serverURL: "https://developers.hostinger.com"
            apiKeySecretRef:
              name: hostinger-credentials
              key: apiToken
```

## Usage Example

Once the Issuer is ready, you can issue a certificate:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  dnsNames:
  - "example.com"
  - "*.example.com"
  issuerRef:
    name: letsencrypt-hostinger
    kind: ClusterIssuer
  secretName: example-com-tls
```

## Development & Testing

### Running the Test Suite
All DNS providers must pass the DNS01 provider conformance testing suite to ensure correct behavior.

1.  **Prepare Test Data:**
    Edit the `config.yaml` file found in `testdata/hostinger/`.

    You may need to hardcode api token for testing purposes since `config.yaml` only contains secret ref.

2.  **Run Tests:**
    You must provide a real domain you control (zone) for the test to write DNS records to.

    ```bash
    TEST_ZONE_NAME=example.com. make test
    ```