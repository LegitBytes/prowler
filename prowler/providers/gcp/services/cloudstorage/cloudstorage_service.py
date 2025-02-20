from typing import Optional
from pydantic import BaseModel
from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService

class Bucket(BaseModel):
    name: str
    id: str
    region: str
    uniform_bucket_level_access: bool
    public: bool
    project_id: str
    retention_policy: Optional[dict]
    encryption: Optional[dict] = None   # New field for encryption settings

class CloudStorage(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__("storage", provider)
        self.buckets = []
        self._get_buckets()
        # For each bucket, retrieve encryption settings
        self.__threading_call__(self._get_bucket_encryption, self.buckets)

    def _get_buckets(self):
        for project_id in self.project_ids:
            try:
                request = self.client.buckets().list(project=project_id)
                while request is not None:
                    response = request.execute()
                    for bucket in response.get("items", []):
                        bucket_iam = (
                            self.client.buckets()
                            .getIamPolicy(bucket=bucket["id"])
                            .execute()["bindings"]
                        )
                        public = False
                        if "allAuthenticatedUsers" in str(bucket_iam) or "allUsers" in str(bucket_iam):
                            public = True
                        self.buckets.append(
                            Bucket(
                                name=bucket["name"],
                                id=bucket["id"],
                                region=bucket["location"],
                                uniform_bucket_level_access=bucket["iamConfiguration"]["uniformBucketLevelAccess"]["enabled"],
                                public=public,
                                retention_policy=bucket.get("retentionPolicy"),
                                project_id=project_id,
                            )
                        )
                    request = self.client.buckets().list_next(previous_request=request, previous_response=response)
            except Exception as error:
                logger.error(f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}")

    def _get_bucket_encryption(self, bucket: Bucket):
        logger.info(f"CloudStorage - Get encryption for bucket: {bucket.name}")
        try:
            # Retrieve full bucket metadata to include encryption settings.
            request = self.client.buckets().get(bucket=bucket.id, project=bucket.project_id, projection="full")
            response = request.execute()
            # The encryption field is in response['encryption'] if set.
            bucket.encryption = response.get("encryption")
        except Exception as error:
            logger.error(f"Error retrieving encryption for bucket {bucket.name}: {error}")

