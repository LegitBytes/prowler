from pydantic import BaseModel
from prowler.lib.logger import logger
from prowler.providers.gcp.lib.service.service import GCPService
import json

# Define a Pydantic model for a Certificate resource.
class Certificate(BaseModel):
    name: str
    id: str
    create_time: str
    expire_time: str = ""  # Defaults to empty string if not provided.
    project_id: str
    managed: dict = None         # Will be present if the certificate is managed.
    selfManaged: dict = None     # Will be present if the certificate is self-managed.
    sanDnsnames: list = []       # Optional list of SAN DNS names.

class CertificateManager(GCPService):
    def __init__(self, provider):
        # Certificate Manager API is available at version "v1".
        # Use "certificatemanager" as the service name.
        super().__init__(__class__.__name__, provider, region="global", api_version="v1")
        self.certificates = []
        self._get_certificates()

    def _get_certificates(self):
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .locations()
                    .certificates()
                    .list(parent=f"projects/{project_id}/locations/global")
                )
                while request is not None:
                    response = request.execute()
                    _certificates = response.get("certificates", [])
                    for cert in _certificates:
                        self.certificates.append(
                            Certificate(
                                name=cert.get("displayName", cert["name"]),
                                id=cert["name"],
                                create_time=cert.get("createTime", ""),
                                expire_time=cert.get("expireTime", ""),  # Will be empty string if not provided.
                                project_id=project_id,
                                managed=cert.get("managed"),
                                selfManaged=cert.get("selfManaged"),
                                sanDnsnames=cert.get("sanDnsnames", [])
                            )
                        )
                    request = (
                        self.client.projects()
                        .locations()
                        .certificates()
                        .list_next(previous_request=request, previous_response=response)
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
