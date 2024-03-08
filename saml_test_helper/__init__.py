import base64
import dataclasses
import logging
import time
import urllib.parse
import zlib
from pathlib import Path
from typing import Dict, List, Optional
from xml.etree import ElementTree

import kubernetes
import requests

__all__ = ["SamlK8sTestHelper"]

logger = logging.getLogger("saml_test_helper")


@dataclasses.dataclass
class SamlResponseHttpPost:
    """Represent a SAML response transmitted via the HTTP-POST binding.

    :ivar url: Service provider's endpoint to receive the SAML assertion.
    :ivar data: Dictionary containing the HTML form data for the SAML response.
    """

    url: str
    data: Dict[str, str]
    binding: str = "HTTP-POST"


class SamlK8sTestHelper:
    CERTIFICATE = (Path(__file__).parent / "certs/certificate.pem").read_text()
    CERTIFICATE_HASH = "30be696d"
    SAML_HOST = "saml.canonical.test"

    def __init__(self, idp_address: str, kube_config: Optional[str] = None):
        """Initialize the SAML test helper.

        :param idp_address: IP address of the SAML test IdP.
        :param kube_config: Path to the Kubernetes configuration file.
        """
        self._idp_address = idp_address
        kubernetes.config.load_kube_config(config_file=kube_config)
        self._core_api = kubernetes.client.CoreV1Api()

    @property
    def entity_id(self) -> str:
        """Return the SAML test IdP metadata entity id."""
        return f"https://{self.SAML_HOST}/metadata"

    @property
    def metadata_url(self) -> str:
        """Return the SAML test IdP metadata URL."""
        return f"https://{self.SAML_HOST}/metadata"

    def _run_in_pod(self, namespace: str, pod: str, container: str, command: List[str]) -> str:
        return kubernetes.stream.stream(
            self._core_api.connect_get_namespaced_pod_exec,
            name=pod,
            namespace=namespace,
            container=container,
            command=command,
            stderr=False,
            stdin=False,
            stdout=True,
            tty=False,
        )

    def _get_containers(self, namespace: str, pod: str):
        pod_def = self._core_api.read_namespaced_pod(name=pod, namespace=namespace)
        return [c.name for c in pod_def.spec.containers]

    def _write_file_in_container(
        self,
        namespace: str,
        pod: str,
        container: str,
        path: str,
        content: str,
        append=False,
    ):
        """Write content to a file in all containers of a given pod."""
        logger.debug(
            "%s file, path: %s, container: %s pod: %s, namespace: %s",
            "append" if append else "write",
            path,
            container,
            pod,
            namespace,
        )
        if append:
            existing_content = self._run_in_pod(
                namespace=namespace,
                pod=pod,
                container=container,
                command=["/bin/cat", path],
            )
            content = existing_content + content
        kubernetes.stream.stream(
            self._core_api.connect_get_namespaced_pod_exec,
            name=pod,
            namespace=namespace,
            container=container,
            command=["/bin/cp", "/dev/stdin", path],
            stderr=True,
            stdin=True,
            stdout=True,
            tty=False,
            _preload_content=False,
        ).write_stdin(content)

    def prepare_pod(self, namespace: str, pod: str):
        """Modify the SAML service provider pod for testing purposes.

        This function injects and trusts TLS certificates into the service provider and updates
        the container's hosts file. This ensures the service provider can establish an HTTPS
        connection with the SAML test IdP.

        Certificate modifications are made to:
          - ``/etc/ssl/certs/``
          - ``**/certifi/cacert.pem``

        Additionally, the hosts file at `/etc/hosts` is updated.

        .. note::
            Kubernetes lacks an API for container file modifications. Instead, this function
            relies on GNU utilities, such as ``cat``, ``cp``, and ``find``, to modify files.
            This approach may not be compatible with certain minimal images.

            All changes made are ephemeral and will revert upon container restart.

        :param namespace: The Kubernetes namespace in which the pod is located.
        :param pod: The name of the pod.
        :return: None
        """
        for container in self._get_containers(namespace=namespace, pod=pod):
            logger.info("inject certificate into container: %s, pod: %s", container, pod)
            for cert in ("saml-certificate.pem", f"{self.CERTIFICATE_HASH}.0"):
                self._write_file_in_container(
                    namespace=namespace,
                    pod=pod,
                    container=container,
                    path=f"/etc/ssl/certs/{cert}",
                    content=self.CERTIFICATE,
                )
            certifi_certs = self._run_in_pod(
                namespace=namespace,
                pod=pod,
                container=container,
                command=[
                    "find",
                    "/",
                    "-type",
                    "f",
                    "-wholename",
                    "*/certifi/cacert.pem",
                ],
            )
            for certifi_cert in certifi_certs.strip().splitlines():
                self._write_file_in_container(
                    namespace=namespace,
                    pod=pod,
                    container=container,
                    path=certifi_cert,
                    content=f"\n{self.CERTIFICATE}",
                    append=True,
                )
            logger.info("inject host into container: %s, pod: %s", container, pod)
            self._write_file_in_container(
                namespace=namespace,
                pod=pod,
                container=container,
                path="/etc/hosts",
                content=f"\n{self._idp_address} {self.SAML_HOST}\n",
                append=True,
            )

    @classmethod
    def deploy_saml_idp(
        cls,
        namespace: str,
        kube_config: Optional[str] = None,
        timeout: int = 300,
        image="ghcr.io/canonical/saml-test-idp:0.1.1",
    ) -> "SamlK8sTestHelper":
        """Deploy a SAML test IdP in Kubernetes and return the helper instance.

        This method deploys a SAML test IdP server as a pod within the specified Kubernetes
        namespace. After successful deployment, it returns a ``SamlK8sTestHelper``
        instance for interactions with the deployed SAML test IdP.

        :param namespace: The Kubernetes namespace to deploy the SAML test IdP pod.
        :param kube_config: Path to the kubeconfig.
        :param timeout: Timeout (in seconds) for the deployment. Default is 300 seconds.
        :param image: Docker image for the SAML test IdP.
        :return: Instance of ``SamlK8sTestHelper`` for the deployed SAML test IdP.
        """
        kubernetes.config.load_kube_config(config_file=kube_config)
        core_api = kubernetes.client.CoreV1Api()
        pod_manifest = kubernetes.client.V1Pod(
            api_version="v1",
            metadata=kubernetes.client.V1ObjectMeta(
                namespace=namespace,
                name="saml-test-idp",
            ),
            spec=kubernetes.client.V1PodSpec(
                containers=[
                    kubernetes.client.V1Container(
                        name="saml-test-idp", image=image, image_pull_policy="Always"
                    )
                ]
            ),
        )
        pod = core_api.create_namespaced_pod(namespace=namespace, body=pod_manifest)
        deadline = time.time() + timeout
        while time.time() < deadline:
            pod_status = core_api.read_namespaced_pod_status(pod.metadata.name, namespace)
            if pod_status.status.phase == "Running" and pod_status.status.pod_ip:
                pod_ip = pod_status.status.pod_ip
                return cls(idp_address=pod_ip, kube_config=kube_config)
            time.sleep(1)
        raise TimeoutError("timed out waiting for the pod to start and obtain an IP address")

    def register_service_provider(self, name: str, metadata: str) -> None:
        """Register a service provider with the SAML test IdP.

        :param name: Unique identifier for the service provider in the SAML test IdP.
        :param metadata: XML metadata of the service provider to be registered.
        """
        response = requests.put(
            f"http://{self._idp_address}/services/{name}",
            data=metadata,
            headers={"Content-Type": "application/xml"},
            timeout=10,
        )
        response.raise_for_status()

    def redirect_sso_login(
        self, redirect_url: str, username: str = "ubuntu", password: str = "ubuntu"
    ) -> SamlResponseHttpPost:
        """Execute identity provider steps of SSO login process.

        This method runs the identity provider steps of SSO login process during the service
        provider initiated. The ``redirect_url`` is typically where the service provider redirects
        users for authentication with the identity provider. You can obtain this URL by initiating
        a login request on the service provider's website.

        After executing all identity provider steps, this method returns a
        ``SamlResponseHttpPost`` instance. This object encapsulates the SAML assertion, which
        should be sent back to the service provider to complete the SSO process.

        :param redirect_url: URL where the service provider redirects for IdP authentication.
        :param username: Username for SSO login, defaulting to "ubuntu".
        :param password: Password for SSO login, defaulting to "ubuntu".
        :return: A ``SamlResponseHttpPost`` object encapsulating the SAML response.
        """
        url = urllib.parse.urlparse(redirect_url)
        if url.netloc != self.SAML_HOST:
            raise ValueError(
                f"expected redirect_url to SAML IdP SSO login, but got '{redirect_url}'"
            )
        query = dict(urllib.parse.parse_qsl(url.query))
        compressed_saml_request = base64.b64decode(query["SAMLRequest"])
        saml_request = zlib.decompress(compressed_saml_request, -zlib.MAX_WBITS)
        session = requests.Session()
        session.trust_env = False
        response = session.post(
            f"http://{self._idp_address}/sso",
            data={
                "user": username,
                "password": password,
                "SAMLRequest": base64.b64encode(saml_request).decode("ascii"),
                "RelayState": query["RelayState"],
            },
            timeout=10,
        )
        response.raise_for_status()
        if "Invalid username or password" in response.text:
            raise ValueError("invalid username or password")
        tree = ElementTree.fromstring(response.text)
        post_form = tree.find("form")
        if post_form is None:
            raise ValueError("form element for SAML assertion missing in the SAML response")
        post_url = post_form.attrib["action"]
        inputs = {
            node.attrib["name"]: node.attrib["value"]
            for node in tree.iter("input")
            if "name" in node.attrib and "value" in node.attrib
        }
        return SamlResponseHttpPost(url=post_url, data=inputs)
