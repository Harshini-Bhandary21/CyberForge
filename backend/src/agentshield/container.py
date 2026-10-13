"""Dependency wiring. One Container = one fully-assembled AgentShield instance over one Store."""

from __future__ import annotations

from dataclasses import dataclass

from agentshield.config import Settings
from agentshield.core.agents import AgentRegistry
from agentshield.core.anchor import Anchors
from agentshield.core.approvals import ApprovalService
from agentshield.core.guard import GuardService
from agentshield.core.policy import PolicyConfig
from agentshield.core.sessions import SessionService
from agentshield.core.verifier import HeuristicVerifier, IntentVerifier, build_verifier
from agentshield.llm.client import LLM
from agentshield.modules.anomaly.engine import AnomalyEngine
from agentshield.modules.fraud.engine import FraudEngine
from agentshield.modules.incidents.service import IncidentService
from agentshield.storage import open_store
from agentshield.storage.store import Store


@dataclass
class Container:
    settings: Settings
    store: Store  # or PostgresStore (same interface)
    llm: LLM
    agents: AgentRegistry
    approvals: ApprovalService
    anomaly: AnomalyEngine
    fraud: FraudEngine
    incidents: IncidentService
    sessions: SessionService
    guard: GuardService
    anchors: Anchors


def build_container(
    settings: Settings,
    store: Store | None = None,
    *,
    policy: PolicyConfig | None = None,
    heuristic_only: bool = False,
) -> Container:
    if store is None:
        url = settings.database_url.get_secret_value() if settings.database_url else None
        store = open_store(url, settings.db_path)
    llm = LLM(settings)
    verifier: IntentVerifier = HeuristicVerifier() if heuristic_only else build_verifier(llm)
    agents = AgentRegistry(store, settings.agent_signing_secret.get_secret_value())
    approvals = ApprovalService(store)
    anomaly = AnomalyEngine(store)
    fraud = FraudEngine(store, settings)
    incidents = IncidentService(
        store,
        agents,
        LLM(settings.model_copy(update={"use_llm": False})) if heuristic_only else llm,
    )
    sessions = SessionService(store, settings, agents, incidents, anomaly)
    guard = GuardService(
        store, settings, sessions, agents, approvals, verifier, anomaly, fraud, incidents, policy
    )
    return Container(
        settings,
        store,
        llm,
        agents,
        approvals,
        anomaly,
        fraud,
        incidents,
        sessions,
        guard,
        Anchors(
            store, settings.agent_signing_secret.get_secret_value(), settings.anchor_export_path
        ),
    )
