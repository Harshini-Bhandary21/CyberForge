import pytest
from fastapi.testclient import TestClient

from agentshield.config import Settings
from agentshield.container import Container, build_container
from agentshield.main import create_app
from agentshield.storage.store import Store


@pytest.fixture
def settings() -> Settings:
    return Settings(db_path=":memory:", use_llm=False)


@pytest.fixture
def c(settings: Settings) -> Container:
    return build_container(settings, Store(":memory:"), heuristic_only=True)


@pytest.fixture
def client(c: Container, settings: Settings) -> TestClient:
    return TestClient(create_app(settings, c))
