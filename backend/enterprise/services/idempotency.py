from typing import Any

class IdempotencyService:
    def __init__(self, redis_client: Any):
        self.redis = redis_client

    def is_idempotent(self, key: str) -> bool:
        return self.redis.get(key) is not None

    def mark_idempotent(self, key: str, value: str, ttl: int = 3600) -> None:
        self.redis.set(key, value, ex=ttl)
