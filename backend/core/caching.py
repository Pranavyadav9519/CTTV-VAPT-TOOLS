"""
Redis caching module for query and session caching
"""

import redis
import json
import os
from typing import Any, Optional, Callable
from functools import wraps
import hashlib


class CacheManager:
    """Manages all caching operations using Redis"""
    
    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            value = self.redis_client.get(key)
            if value:
                return json.loads(value)
        except (redis.RedisError, json.JSONDecodeError):
            return None
    
    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """Set value in cache with TTL"""
        try:
            self.redis_client.setex(
                key,
                ttl,
                json.dumps(value, default=str)
            )
            return True
        except redis.RedisError:
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            self.redis_client.delete(key)
            return True
        except redis.RedisError:
            return False
    
    def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        try:
            keys = self.redis_client.keys(pattern)
            if keys:
                return self.redis_client.delete(*keys)
            return 0
        except redis.RedisError:
            return 0
    
    @staticmethod
    def _generate_key(prefix: str, *args, **kwargs) -> str:
        """Generate cache key from prefix and parameters"""
        key_parts = [prefix]
        
        # Add positional args
        for arg in args:
            key_parts.append(str(arg))
        
        # Add keyword args (sorted for consistency)
        for k, v in sorted(kwargs.items()):
            key_parts.append(f"{k}={v}")
        
        return ":".join(key_parts)


# Global cache manager instance
_cache = CacheManager()


def cached(prefix: str, ttl: int = 3600):
    """Decorator to cache function results"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = CacheManager._generate_key(prefix, *args, **kwargs)
            
            # Try to get from cache
            cached_value = _cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Compute value
            result = func(*args, **kwargs)
            
            # Store in cache
            _cache.set(cache_key, result, ttl)
            
            return result
        
        return wrapper
    
    return decorator


def invalidate_cache(pattern: str):
    """Invalidate cache matching pattern"""
    return _cache.clear_pattern(pattern)


# Cache key prefixes for different types
CACHE_PREFIXES = {
    'scan': 'cache:scan',
    'device': 'cache:device',
    'vulnerability': 'cache:vulnerability',
    'report': 'cache:report',
    'user': 'cache:user',
    'stats': 'cache:stats',
}


# TTL configurations (in seconds)
CACHE_TTLS = {
    'session': 86400,          # 24 hours
    'user': 3600,              # 1 hour
    'scan': 600,               # 10 minutes
    'device': 600,             # 10 minutes
    'vulnerability': 1800,     # 30 minutes
    'report': 3600,            # 1 hour
    'stats': 300,              # 5 minutes
}


# Example usage decorators
def get_cache_manager():
    """Get global cache manager instance"""
    return _cache
