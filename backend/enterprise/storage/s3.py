from typing import Any

class S3Client:
    def __init__(self, bucket: str):
        self.bucket = bucket

    def put_object(self, key: str, body: bytes) -> None:
        # Implement actual S3 upload logic
        pass
