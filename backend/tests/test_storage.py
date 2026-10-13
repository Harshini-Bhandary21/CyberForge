import os
import threading

import pytest

from agentshield.storage import open_store
from agentshield.storage.store import Store

PG_URL = os.getenv("TEST_DATABASE_URL")


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgres", marks=pytest.mark.skipif(not PG_URL, reason="TEST_DATABASE_URL not set")
        ),
    ]
)
def store(request):
    s = Store(":memory:") if request.param == "sqlite" else open_store(PG_URL)
    s.reset()
    yield s
    s.reset()
    if request.param == "postgres":
        s.close()


def test_documents_roundtrip(store):
    store.put("things", "a", {"x": 1})
    store.put("things", "a", {"x": 2})  # upsert
    store.put("things", "b", {"x": 3})
    assert store.get("things", "a") == {"x": 2}
    assert {d["x"] for d in store.list("things")} == {2, 3}
    store.delete("things", "a")
    assert store.get("things", "a") is None


def test_audit_chain_and_filters(store):
    for i in range(5):
        store.append_event("t.one" if i % 2 else "t.two", {"i": i}, session_id="s1", agent_id="a1")
    assert store.verify_chain()["valid"] and store.count_events() == 5
    assert store.count_events("t.one") == 2
    assert len(store.events(types=["t.two"])) == 3
    assert [e["payload"]["i"] for e in store.events(oldest_first=True, limit=2)] == [0, 1]


def test_secrets_are_never_persisted(store):
    store.put("docs", "x", {"body": "key sk-live-9f8e7d6c5b4a3f2e1d0c and AKIAABCDEFGHIJKLMNOP"})
    store.append_event("e", {"note": "token=supersecretvalue1"})
    assert "sk-live" not in str(store.get("docs", "x")) and "AKIA" not in str(
        store.get("docs", "x")
    )
    assert "supersecret" not in str(store.events()[0]["payload"])
    assert store.verify_chain()["valid"]  # redaction happens before hashing


def test_concurrent_appends_keep_one_valid_chain(store):
    def work():
        for _ in range(15):
            store.append_event("c", {"n": 1})

    threads = [threading.Thread(target=work) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    chain = store.verify_chain()
    assert chain["valid"] and chain["length"] == 60


def test_factory_selects_backend(tmp_path):
    assert isinstance(open_store(None, ":memory:"), Store)
    assert isinstance(open_store(f"sqlite:///{tmp_path}/x.db"), Store)
    if PG_URL:
        s = open_store(PG_URL)
        assert type(s).__name__ == "PostgresStore"
        s.close()


def test_sqlite_tamper_detected():
    s = Store(":memory:")
    s.append_event("a", {"v": 1})
    s.append_event("b", {"v": 2})
    s._db.execute("UPDATE events SET payload='{\"v\":999}' WHERE id=1")
    assert s.verify_chain() == {"valid": False, "length": 2, "broken_at": 1}


@pytest.mark.skipif(not PG_URL, reason="TEST_DATABASE_URL not set")
def test_postgres_tamper_detected():
    s = open_store(PG_URL)
    s.reset()
    s.append_event("a", {"v": 1})
    s.append_event("b", {"v": 2})
    with s._pool.connection() as conn:
        conn.execute(
            "UPDATE events SET payload='{\"v\":999}' WHERE id=(SELECT min(id) FROM events)"
        )
    assert s.verify_chain()["valid"] is False
    s.reset()
    s.close()


@pytest.mark.skipif(not PG_URL, reason="TEST_DATABASE_URL not set")
def test_full_platform_runs_on_postgres():
    from agentshield.config import Settings
    from agentshield.container import build_container
    from agentshield.demo.scenario import run

    s = open_store(PG_URL)
    s.reset()
    c = build_container(Settings(use_llm=False), s, heuristic_only=True)
    assert len(run(c)["steps"]) == 10
    assert c.store.verify_chain()["valid"] and len(c.incidents.list()) >= 1
    s.reset()
    s.close()
