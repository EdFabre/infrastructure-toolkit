"""
Thread-safe TTL cache for infrastructure-toolkit.

Provides a simple, thread-safe time-to-live (TTL) cache for caching server metrics,
container data, and other expensive operations.
"""

import time
from threading import RLock
from typing import Any, Optional, Dict
from dataclasses import dataclass


@dataclass
class CacheEntry:
    """Represents a cached value with expiration."""
    value: Any
    expires_at: float


class TTLCache:
    """
    Thread-safe time-to-live cache.

    Features:
    - Automatic expiration of entries after TTL
    - Thread-safe operations with RLock
    - Auto-cleanup of expired entries on access
    - Configurable default TTL

    Usage:
        cache = TTLCache(default_ttl=60)
        cache.set("key", {"data": "value"})
        result = cache.get("key")  # Returns {"data": "value"} or None
    """

    def __init__(self, default_ttl: int = 60):
        """
        Initialize TTL cache.

        Args:
            default_ttl: Default time-to-live in seconds (default: 60)
        """
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = RLock()
        self._default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache if not expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found or expired
        """
        with self._lock:
            # Auto-cleanup expired entry
            if key in self._cache:
                entry = self._cache[key]
                if time.time() >= entry.expires_at:
                    del self._cache[key]
                    return None
                return entry.value
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        Set value in cache with TTL.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default_ttl if None)
        """
        with self._lock:
            ttl_seconds = ttl if ttl is not None else self._default_ttl
            expires_at = time.time() + ttl_seconds
            self._cache[key] = CacheEntry(value=value, expires_at=expires_at)

    def invalidate(self, key: str) -> bool:
        """
        Invalidate (delete) a cache entry.

        Args:
            key: Cache key to invalidate

        Returns:
            True if key was found and deleted, False otherwise
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()

    def cleanup_expired(self) -> int:
        """
        Manually cleanup all expired entries.

        Returns:
            Number of entries removed
        """
        with self._lock:
            now = time.time()
            expired_keys = [
                key for key, entry in self._cache.items()
                if now >= entry.expires_at
            ]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)

    def size(self) -> int:
        """
        Get current cache size (including expired entries).

        Returns:
            Number of entries in cache
        """
        with self._lock:
            return len(self._cache)

    def stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats (size, expired count)
        """
        with self._lock:
            now = time.time()
            total = len(self._cache)
            expired = sum(
                1 for entry in self._cache.values()
                if now >= entry.expires_at
            )
            active = total - expired

            return {
                "total_entries": total,
                "active_entries": active,
                "expired_entries": expired,
                "default_ttl": self._default_ttl,
            }
