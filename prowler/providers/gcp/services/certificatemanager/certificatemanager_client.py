from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.certificatemanager.certificatemanager_service import CertificateManager

certificatemanager_client = CertificateManager(Provider.get_global_provider())
