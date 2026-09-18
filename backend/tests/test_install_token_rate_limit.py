"""Per-install rate-limit keying (INSTALL_TOKEN_ENABLED — default OFF).

Spike scope only: when the flag is on AND a request carries a syntactically
valid X-Install-Token header, the limiter keys on install:<token> INSTEAD of
the client IP. Anything else (flag off, missing header, invalid token)
behaves exactly like the pre-existing IP keying. The token is caller-supplied
and freely rotatable, so the tests here pin behaviour under churn — the
bounded in-memory keyspace is the honest mitigation, and 429/Retry-After
semantics must be identical to the IP path.

Every test builds a fresh app + fresh middleware, and toggles the flag via
monkeypatch (auto-restored): nothing here mutates app.main._RATE_MAX,
_RATE_WINDOW, RateLimitMiddleware.__init__.__defaults__, or the app
singleton, so test_rate_limit's defaults-pin invariant holds regardless of
import order.
"""

import time

import fakeredis
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings, settings
from app.main import InMemoryRateStore, RateLimitMiddleware, RedisRateStore

# Both tokens stay inside ^[A-Za-z0-9._-]{1,64}$ (covers '.', '_' and '-').
TOKEN_A = "install-token-alpha"
TOKEN_B = "install_token.beta-2"

RATE_LIMITED_DETAIL = "Rate limit exceeded. Try again later."


def _tiny_client(monkeypatch, *, enabled, store=None, max_requests=3, window=60):
    """Fresh app + fresh limiter per test; flag toggled with auto-restore.

    Two routes so tests can prove the token key is shared across paths
    (i.e. never combined with the path). Store is returned so key-level
    assertions can pin exactly what was used as the rate-limit key.
    """
    monkeypatch.setattr(settings, "INSTALL_TOKEN_ENABLED", enabled)
    if store is None:
        store = InMemoryRateStore()
    tiny = FastAPI()

    @tiny.get("/ping")
    def ping():
        return {"ok": True}

    @tiny.get("/ping/other")
    def ping_other():
        return {"ok": True}

    tiny.add_middleware(
        RateLimitMiddleware, max_requests=max_requests, window=window, store=store
    )
    return TestClient(tiny), store


class TestFlagConfiguration:
    def test_settings_default_is_off(self):
        # Field default, independent of env: a fresh deployment ships disabled.
        assert Settings.model_fields["INSTALL_TOKEN_ENABLED"].default is False

    def test_flag_is_read_from_settings_at_construction(self, monkeypatch):
        monkeypatch.setattr(settings, "INSTALL_TOKEN_ENABLED", True)
        on = RateLimitMiddleware(
            FastAPI(), max_requests=1, window=60, store=InMemoryRateStore()
        )
        assert on.install_token_enabled is True

        monkeypatch.setattr(settings, "INSTALL_TOKEN_ENABLED", False)
        off = RateLimitMiddleware(
            FastAPI(), max_requests=1, window=60, store=InMemoryRateStore()
        )
        assert off.install_token_enabled is False


class TestFlagOff:
    def test_token_header_ignored_and_ip_keying_unchanged(self, monkeypatch):
        """Flag OFF: the header changes nothing — one shared IP bucket."""
        client, store = _tiny_client(monkeypatch, enabled=False, max_requests=3)

        for _ in range(3):
            resp = client.get("/ping", headers={"X-Install-Token": TOKEN_A})
            assert resp.status_code == 200
        # A *different* token must still be blocked: both tokens fell into the
        # same IP-limited bucket because the header was ignored.
        resp = client.get("/ping", headers={"X-Install-Token": TOKEN_B})
        assert resp.status_code == 429
        assert resp.json()["detail"] == RATE_LIMITED_DETAIL

        # Exactly one key — the client IP — was ever used.
        assert set(store._hits) == {"testclient"}


class TestFlagOn:
    def test_distinct_tokens_get_independent_quotas(self, monkeypatch):
        client, store = _tiny_client(monkeypatch, enabled=True, max_requests=2)

        for _ in range(2):
            resp = client.get("/ping", headers={"X-Install-Token": TOKEN_A})
            assert resp.status_code == 200
        # A's quota is now exhausted, but B is a separate key.
        assert (
            client.get("/ping", headers={"X-Install-Token": TOKEN_A}).status_code
            == 429
        )
        resp = client.get("/ping", headers={"X-Install-Token": TOKEN_B})
        assert resp.status_code == 200

        assert set(store._hits) == {
            f"install:{TOKEN_A}",
            f"install:{TOKEN_B}",
        }

    def test_same_token_exceeds_limit_gets_429_and_retry_after(self, monkeypatch):
        client, _ = _tiny_client(monkeypatch, enabled=True, max_requests=2)

        for _ in range(2):
            assert (
                client.get("/ping", headers={"X-Install-Token": TOKEN_A}).status_code
                == 200
            )
        resp = client.get("/ping", headers={"X-Install-Token": TOKEN_A})
        assert resp.status_code == 429
        # Same response contract as the IP path.
        assert resp.json()["detail"] == RATE_LIMITED_DETAIL
        assert int(resp.headers["Retry-After"]) >= 1

    def test_missing_header_falls_back_to_ip(self, monkeypatch):
        client, store = _tiny_client(monkeypatch, enabled=True, max_requests=2)

        for _ in range(2):
            assert client.get("/ping").status_code == 200
        resp = client.get("/ping")
        assert resp.status_code == 429
        assert set(store._hits) == {"testclient"}

        # The IP bucket and install buckets are independent: a valid token
        # after IP exhaustion gets its own fresh quota.
        resp = client.get("/ping", headers={"X-Install-Token": TOKEN_A})
        assert resp.status_code == 200

    def test_invalid_token_falls_back_to_ip(self, monkeypatch):
        """Whitespace/punctuation tokens fail validation → IP bucket."""
        client, store = _tiny_client(monkeypatch, enabled=True, max_requests=2)
        bad = "bad token!!"

        for _ in range(2):
            assert (
                client.get("/ping", headers={"X-Install-Token": bad}).status_code
                == 200
            )
        # A *different* invalid token shares the same IP bucket.
        resp = client.get("/ping", headers={"X-Install-Token": "also|invalid"})
        assert resp.status_code == 429
        assert set(store._hits) == {"testclient"}

    def test_oversized_token_falls_back_to_ip(self, monkeypatch):
        client, store = _tiny_client(monkeypatch, enabled=True, max_requests=2)
        too_long = "x" * 65

        for _ in range(2):
            assert (
                client.get("/ping", headers={"X-Install-Token": too_long}).status_code
                == 200
            )
        assert client.get("/ping", headers={"X-Install-Token": too_long}).status_code == 429
        assert set(store._hits) == {"testclient"}

    def test_token_key_replaces_ip_and_never_combines_with_path(self, monkeypatch):
        """One install:<token> key covers every path; the IP is not in it."""
        client, store = _tiny_client(monkeypatch, enabled=True, max_requests=2)

        assert (
            client.get("/ping", headers={"X-Install-Token": TOKEN_A}).status_code
            == 200
        )
        assert (
            client.get("/ping/other", headers={"X-Install-Token": TOKEN_A}).status_code
            == 200
        )
        # Two paths, one token, one shared quota: third request is over.
        resp = client.get("/ping", headers={"X-Install-Token": TOKEN_A})
        assert resp.status_code == 429

        # The key is exactly install:<token> — no IP, no path segments.
        assert set(store._hits) == {f"install:{TOKEN_A}"}


class TestKeyspaceCap:
    """Rotating attacker tokens must not grow memory unboundedly."""

    def test_cap_evicts_dormant_keys_first(self):
        store = InMemoryRateStore(max_keys=2)
        # Dormant: all timestamps outside the window — no live quota state.
        store._hits["dormant"] = [time.monotonic() - 61]
        assert store.hit("live", 1, 60) is None

        assert store.hit("newcomer", 1, 60) is None  # forces the eviction
        assert set(store._hits) == {"live", "newcomer"}
        assert len(store._hits) <= 2

    def test_cap_falls_back_to_oldest_inserted_when_nothing_dormant(self):
        store = InMemoryRateStore(max_keys=2)
        assert store.hit("a", 1, 60) is None
        assert store.hit("b", 1, 60) is None

        assert store.hit("c", 1, 60) is None  # evicts "a" (oldest inserted)
        assert set(store._hits) == {"b", "c"}

        # Retained keys keep full enforcement — eviction did not reset them.
        assert store.hit("c", 1, 60) is not None

    def test_token_churn_under_middleware_stays_bounded(self, monkeypatch):
        store = InMemoryRateStore(max_keys=5)
        client, _ = _tiny_client(
            monkeypatch, enabled=True, store=store, max_requests=2, window=60
        )

        # 50 distinct tokens, one request each: each is a fresh key, and each
        # rotation past the cap must evict rather than grow the map.
        for i in range(50):
            resp = client.get("/ping", headers={"X-Install-Token": f"rotator-{i}"})
            assert resp.status_code == 200
            assert len(store._hits) <= 5

        assert set(store._hits) == {f"install:rotator-{i}" for i in range(45, 50)}

        # The most recent token still has its remaining quota — one more
        # request (2/2), then the 429 contract applies as usual.
        assert (
            client.get("/ping", headers={"X-Install-Token": "rotator-49"}).status_code
            == 200
        )
        resp = client.get("/ping", headers={"X-Install-Token": "rotator-49"})
        assert resp.status_code == 429
        assert int(resp.headers["Retry-After"]) >= 1


class TestRedisBackend:
    def test_token_keys_keep_the_redis_namespace(self, monkeypatch):
        fake = fakeredis.FakeRedis()
        store = RedisRateStore(fake, InMemoryRateStore())
        client, _ = _tiny_client(
            monkeypatch, enabled=True, store=store, max_requests=2, window=60
        )

        for _ in range(2):
            assert (
                client.get("/ping", headers={"X-Install-Token": TOKEN_A}).status_code
                == 200
            )
        resp = client.get("/ping", headers={"X-Install-Token": TOKEN_A})
        assert resp.status_code == 429
        assert resp.json()["detail"] == RATE_LIMITED_DETAIL
        assert int(resp.headers["Retry-After"]) >= 1

        keys = [k.decode() for k in fake.keys("phishguard:ratelimit:*")]
        assert keys, "expected redis-side counters for the token key"
        for key in keys:
            # Namespace shape is phishguard:ratelimit:<key>:<bucket>; the
            # token alphabet has no ':' so the split stays unambiguous.
            parts = key.split(":")
            assert parts[:4] == ["phishguard", "ratelimit", "install", TOKEN_A]
            assert len(parts) == 5
            assert parts[4].isdigit()
            # The client IP is not part of the key — token replaces it.
            assert "testclient" not in key
