import pytest
from fastapi.testclient import TestClient

from agentshield.config import Settings
from agentshield.container import build_container
from agentshield.main import create_app
from agentshield.storage.store import Store

API = "/api/v1"
KEYS = {"k-agent": "agent", "k-analyst": "analyst", "k-admin": "admin"}


def make(**kw) -> TestClient:
    s = Settings(_env_file=None, use_llm=False, db_path=":memory:", **kw)
    return TestClient(create_app(s, build_container(s, Store(":memory:"), heuristic_only=True)))


def h(key):
    return {"X-API-Key": key}


def test_authentication_required_and_constant_response():
    c = make(api_keys=KEYS)
    assert c.get(f"{API}/overview").status_code == 401
    assert c.get(f"{API}/overview", headers=h("nope")).status_code == 401
    assert c.get(f"{API}/overview", headers=h("")).status_code == 401
    assert c.get(f"{API}/health").status_code == 200  # liveness stays public


def test_role_matrix():
    c = make(api_keys=KEYS)
    # agents may drive the guard but nothing operational
    s = c.post(
        f"{API}/sessions",
        json={"agent_id": "bot", "user_goal": "Summarize my inbox."},
        headers=h("k-agent"),
    )
    assert s.status_code == 201
    sid = s.json()["id"]
    assert (
        c.post(
            f"{API}/sessions/{sid}/guard", json={"tool": "read_inbox"}, headers=h("k-agent")
        ).status_code
        == 200
    )
    for path in (
        "/overview",
        "/approvals",
        "/incidents",
        "/events",
        "/compliance/report",
        "/agents",
    ):
        assert c.get(API + path, headers=h("k-agent")).status_code == 403, path
    # analysts operate, but cannot run/reset the demo or mint agent credentials
    assert c.get(f"{API}/overview", headers=h("k-analyst")).status_code == 200
    assert c.post(f"{API}/demo/run", headers=h("k-analyst")).status_code == 403
    assert c.get(f"{API}/agents/bot/credential", headers=h("k-analyst")).status_code == 403
    # admins can
    assert c.get(f"{API}/agents/bot/credential", headers=h("k-admin")).status_code == 200
    assert c.post(f"{API}/demo/run", headers=h("k-admin")).status_code == 200


def test_reviewer_identity_comes_from_the_key_not_the_request():
    c = make(api_keys=KEYS)
    sid = c.post(
        f"{API}/sessions",
        json={"agent_id": "b", "user_goal": "Run `make build`."},
        headers=h("k-agent"),
    ).json()["id"]
    d = c.post(
        f"{API}/sessions/{sid}/guard",
        json={"tool": "run_shell", "args": {"command": "make build"}},
        headers=h("k-agent"),
    ).json()
    r = c.post(
        f"{API}/approvals/{d['approval_id']}/resolve",
        json={"approve": True, "reviewer": "the CEO"},
        headers=h("k-analyst"),
    ).json()
    assert r["reviewer"].startswith("the CEO (key:") and r["status"] == "approved"


def test_security_headers_and_no_cache():
    r = make().get(f"{API}/health")
    assert (
        r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    )
    assert (
        "default-src 'none'" in r.headers["content-security-policy"]
        and r.headers["cache-control"] == "no-store"
    )


def test_oversized_body_rejected():
    c = make(max_body_bytes=1000)
    r = c.post(f"{API}/sessions", json={"agent_id": "a", "user_goal": "x" * 5000})
    assert r.status_code == 413


def test_input_validation_limits():
    c = make()
    assert (
        c.post(f"{API}/sessions", json={"agent_id": "bad id!", "user_goal": "g"}).status_code == 422
    )
    assert (
        c.post(f"{API}/sessions", json={"agent_id": "ok", "user_goal": "x" * 2001}).status_code
        == 422
    )


def test_rate_limit():
    c = make(rate_limit_per_min=5)
    codes = [c.get(f"{API}/overview").status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429] * 3
    assert c.get(f"{API}/health").status_code == 200  # health is exempt


def test_production_refuses_insecure_config():
    with pytest.raises(RuntimeError, match="API key"):
        create_app(Settings(_env_file=None, env="production"))
    with pytest.raises(RuntimeError, match="SIGNING_SECRET"):
        create_app(Settings(_env_file=None, env="production", api_keys=KEYS))


def test_production_hides_docs_and_demo():
    s = Settings(
        _env_file=None,
        env="production",
        api_keys=KEYS,
        agent_signing_secret="x" * 40,
        use_llm=False,
        db_path=":memory:",
    )
    c = TestClient(create_app(s, build_container(s, Store(":memory:"), heuristic_only=True)))
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404
    assert c.post(f"{API}/demo/run", headers=h("k-admin")).status_code == 404


def test_secrets_redacted_in_stored_decisions_and_approvals_still_bind():
    c = make()
    sid = c.post(
        f"{API}/sessions",
        json={"agent_id": "a", "user_goal": "Reply to p@mitaoe.ac.in with status."},
    ).json()["id"]
    secret = "sk-live-9f8e7d6c5b4a3f2e1d0c"
    d = c.post(
        f"{API}/sessions/{sid}/guard",
        json={"tool": "reply_email", "args": {"to": "p@mitaoe.ac.in", "body": f"key {secret}"}},
    ).json()
    assert d["verdict"] == "block" and secret not in str(d)
    assert secret not in str(c.get(f"{API}/decisions").json()) and secret not in str(
        c.get(f"{API}/events?limit=500").json()
    )

    # approval binds to the ORIGINAL args even though stored args are redacted
    sid2 = c.post(
        f"{API}/sessions", json={"agent_id": "a", "user_goal": "Run `make build`."}
    ).json()["id"]
    body = {"tool": "run_shell", "args": {"command": f"make build TOKEN={secret}"}}
    d2 = c.post(f"{API}/sessions/{sid2}/guard", json=body).json()
    assert d2["verdict"] == "require_approval"
    apr = c.get(f"{API}/approvals").json()[0]
    assert secret not in str(apr)
    c.post(f"{API}/approvals/{apr['id']}/resolve", json={"approve": True})
    d3 = c.post(
        f"{API}/sessions/{sid2}/guard", json={**body, "approval_id": d2["approval_id"]}
    ).json()
    assert d3["verdict"] == "allow"
