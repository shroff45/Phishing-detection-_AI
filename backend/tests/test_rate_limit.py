"""Tests for the sliding-window rate limiter and its optional Redis backend."""

import sys
import time
from unittest.mock import patch

import fakeredis
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Patch settings before importing app so RATE_LIMIT is deterministic and no
# real Redis is contacted during import.
with patch("app.config.settings") as _mock_settings:
    _mock_settings.RATE_LIMIT = "5/second"
    _mock_settings.EXTENSION_API_KEY = ""
    _mock_settings.REDIS_URL = "redis://localhost:6379/0"
    _mock_settings.PHISHTANK_API_KEY = ""
    _mock_settings.VIRUSTOTAL_API_KEY = ""
    _mock_settings.GOOGLE_SAFE_BROWSING_KEY = ""
    _mock_settings.HOST = "0.0.0.0"
    _mock_settings.PORT = 7860
    _mock_settings.DEBUG = True
    from app.main import (
        RateLimitMiddleware,
        RedisRateStore,
        InMemoryRateStore,
        _build_rate_store,
        _parse_rate_limit,
        app,
    )

# ── Decontamination: undo what the patched import leaked ────────────────────
# patch() restores app.config.settings on exit, but every module that was first
# imported INSIDE the block did `from app.config import settings` and is left
# permanently bound to the mock: app.main, app.middleware.auth,
# app.services.threat_intel. verify_api_key then reads the mock's
# EXTENSION_API_KEY ("") for the rest of the process, so other test modules'
# monkeypatching of the real settings silently does nothing
# (test_sandbox_crawler.TestDetonateAuth), and nothing can ever turn auth on.
# Rebind every leaked reference back to the real settings object.
from app.config import settings as _real_settings

for _module in list(sys.modules.values()):
    if _module is not None and getattr(_module, "settings", None) is _mock_settings:
        _module.settings = _real_settings


def _get_rate_limiter():
    """Walk the (lazily built) middleware stack to find RateLimitMiddleware."""
    if app.middleware_stack is None:
        app.middleware_stack = app.build_middleware_stack()
    mw = app.middleware_stack
    while hasattr(mw, "app"):
        if hasattr(mw, "max_requests"):
            return mw
        mw = mw.app
    return None


# The middleware class defaults were baked at class-definition time from the
# mock's RATE_LIMIT ("5/second"), so the app singleton's limiter instance would
# otherwise keep that tiny limit for every other module in this pytest process
# (sandbox/api tests then get 429 instead of their expected responses). Reset
# it to the real settings' limits with a fresh store, leaving the shared app
# exactly as a normal (unpatched) import would have built it.
_real_max, _real_window = _parse_rate_limit(_real_settings.RATE_LIMIT)

_singleton_limiter = _get_rate_limiter()
if _singleton_limiter is not None:
    _singleton_limiter.max_requests, _singleton_limiter.window = (
        _real_max,
        _real_window,
    )
    _singleton_limiter.store = InMemoryRateStore()
    _singleton_limiter.backend = "memory"

# Same purge for the factory path: app.main._RATE_MAX/_RATE_WINDOW were also
# computed from the mock and live on as RateLimitMiddleware.__init__'s default
# arguments. Without this reset, any later no-args instantiation in this
# process (e.g. add_middleware(RateLimitMiddleware) on a scratch app — the
# pattern production itself uses) silently re-inherits the 5/second limit.
# After this module's import, nothing in the process may carry the patched
# values: not the settings bindings, not the singleton, not the class.
import app.main as _app_main

_app_main._RATE_MAX = _real_max
_app_main._RATE_WINDOW = _real_window
RateLimitMiddleware.__init__.__defaults__ = (_real_max, _real_window, None)


def _tiny_client(store=None, max_requests=5, window=60):
    """Fresh app + fresh limiter state per call.

    Behavior tests run against a throwaway app instead of the shared
    singleton, so no fixture has to mutate/restore shared state and module
    ordering in pytest is irrelevant. max_requests stays tight (the limit is
    still exercised); the generous window just keeps the test immune to how
    long the requests themselves take.
    """
    if store is None:
        store = InMemoryRateStore()
    tiny = FastAPI()

    @tiny.get("/ping")
    def ping():
        return {"ok": True}

    tiny.add_middleware(
        RateLimitMiddleware, max_requests=max_requests, window=window, store=store
    )
    return TestClient(tiny)


class TestParseRateLimit:
    def test_parse_minute(self):
        count, window = _parse_rate_limit("100/minute")
        assert count == 100
        assert window == 60

    def test_parse_second(self):
        count, window = _parse_rate_limit("5/second")
        assert count == 5
        assert window == 1

    def test_parse_hour(self):
        count, window = _parse_rate_limit("1000/hour")
        assert count == 1000
        assert window == 3600

    def test_parse_singular_window(self):
        count, window = _parse_rate_limit("10/second")
        assert count == 10
        assert window == 1


class TestRateLimiting:
    def test_allows_requests_under_limit(self):
        """Requests under the limit should all succeed."""
        client = _tiny_client()
        for _ in range(5):
            resp = client.get("/ping")
            assert resp.status_code == 200

    def test_blocks_after_limit_exceeded(self):
        """The 6th request (limit is 5) should return 429."""
        client = _tiny_client()
        for _ in range(5):
            resp = client.get("/ping")
            assert resp.status_code == 200

        resp = client.get("/ping")
        assert resp.status_code == 429
        assert "Rate limit exceeded" in resp.json()["detail"]

    def test_429_includes_retry_after_header(self):
        """The 429 response must include a Retry-After header."""
        client = _tiny_client()
        for _ in range(5):
            client.get("/ping")

        resp = client.get("/ping")
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        retry_after = int(resp.headers["Retry-After"])
        assert retry_after >= 1

    def test_different_clients_get_separate_limits(self):
        """Two different IPs should each get their own quota."""
        store = InMemoryRateStore()

        # Client A exhausts its quota
        for _ in range(5):
            assert store.hit("10.0.0.1", 5, 60) is None
        assert store.hit("10.0.0.1", 5, 60) is not None

        # Client B is unaffected
        assert store.hit("10.0.0.2", 5, 60) is None

    def test_window_resets_after_expiry(self):
        """After the window expires, new requests should be allowed."""
        store = InMemoryRateStore()

        # Simulate requests that are now outside the window
        old_time = time.monotonic() - 61
        store._hits["203.0.113.7"] = [old_time] * 5

        # New request is allowed because the stale timestamps are pruned
        assert store.hit("203.0.113.7", 5, 60) is None


class TestSingletonAppWiring:
    """The shared app keeps the settings-derived limits.

    Regression pin for the cross-module pollution this module used to cause:
    if the patched import above ever leaks tiny limits into the app singleton
    again, sibling test modules (e.g. test_sandbox_crawler) start seeing 429s.
    """

    def test_singleton_uses_settings_derived_limits(self):
        rl = _get_rate_limiter()
        assert rl is not None, "RateLimitMiddleware not found in app stack"
        assert (rl.max_requests, rl.window) == _parse_rate_limit(
            _real_settings.RATE_LIMIT
        )

    def test_middleware_factory_defaults_are_settings_derived(self):
        """No-args construction must not inherit the patched import's values.

        The singleton-instance reset alone is not hermetic: if
        RateLimitMiddleware.__init__ defaults still carry "5/second", any
        later add_middleware(RateLimitMiddleware)/no-args construction in
        this process (the pattern production uses) silently re-inherits the
        tiny limit. Pin the class defaults and the app.main rate constants
        to the real settings.
        """
        import app.main as app_main

        expected = _parse_rate_limit(_real_settings.RATE_LIMIT)
        assert RateLimitMiddleware.__init__.__defaults__[:2] == expected
        assert (app_main._RATE_MAX, app_main._RATE_WINDOW) == expected


class TestStoreSelection:
    """_build_rate_store picks in-memory unless Redis is fully usable."""

    def test_no_redis_url_selects_memory(self):
        """REDIS_URL unset (None) → in-memory store, no Redis attempt."""
        with patch("app.main.settings") as s:
            s.REDIS_URL = None
            store, backend = _build_rate_store()
        assert backend == "memory"
        assert isinstance(store, InMemoryRateStore)

    def test_redis_package_missing_falls_back(self):
        """REDIS_URL set but redis not importable → in-memory, no exception."""
        with patch.dict(sys.modules, {"redis": None}):
            with patch("app.main.settings") as s:
                s.REDIS_URL = "redis://redis.internal:6379/0"
                store, backend = _build_rate_store()
        assert backend == "memory"
        assert isinstance(store, InMemoryRateStore)

    def test_redis_unreachable_falls_back(self):
        """Connection refused at startup → in-memory, no exception."""
        with patch("app.main.settings") as s:
            s.REDIS_URL = "redis://127.0.0.1:1/0"  # nothing listens on port 1
            store, backend = _build_rate_store()
        assert backend == "memory"
        assert isinstance(store, InMemoryRateStore)

    def test_redis_reachable_selects_redis_store(self):
        """REDIS_URL set and PING succeeds → Redis-backed store."""
        with patch("app.main.settings") as s:
            s.REDIS_URL = "redis://redis.internal:6379/0"
            with patch("redis.Redis.from_url", return_value=fakeredis.FakeRedis()):
                store, backend = _build_rate_store()
        assert backend == "redis"
        assert isinstance(store, RedisRateStore)


class TestRedisRateStore:
    """Redis-backed behaviour, exercised against fakeredis (no live server)."""

    def test_counts_shared_across_clients(self):
        """Two clients against one server == two processes sharing a counter."""
        server = fakeredis.FakeServer()
        store_a = RedisRateStore(fakeredis.FakeRedis(server=server), InMemoryRateStore())
        store_b = RedisRateStore(fakeredis.FakeRedis(server=server), InMemoryRateStore())

        for _ in range(3):
            assert store_a.hit("203.0.113.9", 5, 60) is None
        for _ in range(2):
            assert store_b.hit("203.0.113.9", 5, 60) is None
        # 6th hit against the shared counter is over the limit of 5
        retry_after = store_b.hit("203.0.113.9", 5, 60)
        assert retry_after is not None
        assert retry_after >= 1

    def test_request_time_redis_failure_falls_back_to_memory(self):
        """A Redis error mid-request degrades to in-memory, never raises."""
        fallback = InMemoryRateStore()
        store = RedisRateStore(fakeredis.FakeRedis(), fallback)
        assert store.hit("198.51.100.7", 2, 60) is None  # Redis healthy

        with patch.object(store, "_client") as broken:
            broken.pipeline.side_effect = ConnectionError("redis down")
            assert store.hit("198.51.100.7", 2, 60) is None
        assert len(fallback._hits["198.51.100.7"]) == 1

    def test_degraded_store_skips_redis_until_retry_window(self):
        """Once tripped, Redis is not touched again until the cooldown ends."""
        fallback = InMemoryRateStore()
        store = RedisRateStore(fakeredis.FakeRedis(), fallback)
        store._redis_down_until = time.time() + 60

        with patch.object(store, "_client") as broken:
            assert store.hit("192.0.2.1", 2, 60) is None
            broken.pipeline.assert_not_called()
        assert len(fallback._hits["192.0.2.1"]) == 1


class TestRedisBackedMiddleware:
    """The 429/Retry-After contract is identical on the Redis backend."""

    def test_429_and_retry_after_on_redis_path(self):
        store = RedisRateStore(fakeredis.FakeRedis(), InMemoryRateStore())
        client = _tiny_client(store, max_requests=2, window=60)

        assert client.get("/ping").status_code == 200
        assert client.get("/ping").status_code == 200
        resp = client.get("/ping")
        assert resp.status_code == 429
        assert "Rate limit exceeded" in resp.json()["detail"]
        assert int(resp.headers["Retry-After"]) >= 1

    def test_two_app_instances_share_quota_via_redis(self):
        """Two app instances on one Redis share one quota per client IP."""
        server = fakeredis.FakeServer()
        client_a = _tiny_client(
            RedisRateStore(fakeredis.FakeRedis(server=server), InMemoryRateStore()),
            max_requests=2,
            window=60,
        )
        client_b = _tiny_client(
            RedisRateStore(fakeredis.FakeRedis(server=server), InMemoryRateStore()),
            max_requests=2,
            window=60,
        )

        assert client_a.get("/ping").status_code == 200
        assert client_a.get("/ping").status_code == 200
        # Same client IP, other "process": shared counter is already exhausted.
        assert client_b.get("/ping").status_code == 429
