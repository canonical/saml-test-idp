# SAML Test IdP

SAML Test IdP provides a standalone test Identity Provider (IdP) server, built
upon [crewjam/saml](https://github.com/crewjam/saml). It also offers a companion
Python library to streamline testing for SAML service providers.

> **Warning**
> This is strictly for testing purposes only. It should **NOT** be used in any
> other context.

## Getting Started

### 1. Installation

To install the companion Python helper library, use the following command.

```bash
pip install git+https://github.com/canonical/saml-test-idp.git
```

The SAML test IdP server is distributed via a Docker image. Deployment is
handled by the companion helper library.

### 2. Deploying the SAML Test IdP

Within your test suite, use the `SamlK8sTestHelper.deploy_saml_idp` factory to
deploy the SAML Test IdP server into a Kubernetes cluster. It will return an
instance of the helper for further interactions.

```python
from saml_test_helper import SamlK8sTestHelper

saml_helper = SamlK8sTestHelper.deploy_saml_idp(namespace="test-testing")
```

### 3. Preparing Service Provider Pods

Since SAML mandates HTTPS, it's essential to modify the service provider pods to
ensure they trust the SAML Test IdP server's TLS certificates and have the
correct host records in place. This process is simplified with a method provided
by the helper.

```python
saml_helper.prepare_pod(namespace="test-testing", pod="saml-integrator-0")
saml_helper.prepare_pod(namespace="test-testing", pod="synapse-0")
```

**Note**: Always complete this step before configuring the service provider with
the SAML Test IdP, otherwise it will result in errors.

### 4. Registering Service Provider Metadata

For the SAML authentication process, the SAML Test IdP must be aware of the
service provider. Achieve this by registering the service provider's metadata
XML.

```python
saml_helper.register_service_provider(
    name="synapse.local",
    metadata=service_provider_metadata
)
```

### 5. Single Sign-On (SSO) Login Process

With the above steps completed, you're ready to test the login flow. Begin the
login process at the service provider's end. Though the exact path might differ
across service providers, it should result in a redirection to the SAML test IdP
for SSO login. Capture the redirection URL, then pass it to the helper.

Here, the helper completes all steps on the IdP side and returns
a `requests.Request` object holding the assertion. You can then inspect, modify,
or relay this request to the service provider to finalize the login.

```python
next_request = saml_helper.sso_login(redirect_url)
assert "https://synapse.local" in next_request.url

next_request.url = next_request.url.replace(
    "https://synapse.local",
    f"http://{ip}:8080"
)
next_request.headers["Host"] = "synapse.local"
logged_in_page = session.send(next_request.prepare())
```
