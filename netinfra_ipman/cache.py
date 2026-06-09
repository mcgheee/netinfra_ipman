from __future__ import annotations

import json
from typing import Any

from redis import Redis
from redis.exceptions import RedisError


class StatusCache:
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._memory: dict[str, Any] = {}
        self._redis: Redis | None = None
        try:
            self._redis = Redis.from_url(redis_url, decode_responses=True)
            self._redis.ping()
        except RedisError:
            self._redis = None

    @property
    def available(self) -> bool:
        return self._redis is not None

    def get(self, key: str) -> dict[str, Any] | None:
        if self._redis:
            value = self._redis.get(key)
            return json.loads(value) if value else None
        return self._memory.get(key)

    def set(self, key: str, value: dict[str, Any], ttl: int | None = None) -> None:
        if self._redis:
            payload = json.dumps(value)
            if ttl:
                self._redis.setex(key, ttl, payload)
            else:
                self._redis.set(key, payload)
            return
        self._memory[key] = value

    def keys(self, pattern: str) -> list[str]:
        if self._redis:
            return [str(k) for k in self._redis.keys(pattern)]
        prefix = pattern.rstrip("*")
        return [key for key in self._memory if key.startswith(prefix)]
