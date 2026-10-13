"""Command line entry points: ``agentshield serve | demo | redteam``."""

from __future__ import annotations

import argparse
import json

from agentshield.config import get_settings
from agentshield.container import build_container


def doctor(*, live: bool) -> int:
    """Print a configuration report. Exit code 1 when something that matters is wrong."""
    from agentshield.llm.client import LLM

    s = get_settings()
    ok = True

    def line(flag: str, msg: str) -> None:
        print(f"  [{flag}] {msg}")

    print(f"AgentShield doctor (env={s.env})")
    print("Database")
    try:
        c = build_container(s)
        kind = type(c.store).__name__
        c.store.append_event("doctor.ping", {})
        line(
            "ok",
            f"{kind} reachable; audit chain {'intact' if c.store.verify_chain()['valid'] else 'BROKEN'}",
        )
    except Exception as exc:  # noqa: BLE001 - report any connection problem, never the URL
        ok = False
        line("!!", f"cannot open database: {type(exc).__name__}")
    print("API security")
    line(
        "ok" if s.auth_configured else "--",
        "API keys configured"
        if s.auth_configured
        else "no API keys (open access: development only)",
    )
    for problem in s.production_problems():
        flag = "!!" if s.is_production else "--"
        ok = ok and not s.is_production
        line(flag, problem)
    print("LLM providers (order = priority)")
    for name in s.llm_providers:
        line(
            "ok" if s.key_for(name) else "--",
            f"{name}: {'key present' if s.key_for(name) else 'no key (skipped)'}",
        )
    if not s.active_providers:
        line("--", "no provider keys: running on offline heuristics")
    if live and s.active_providers:
        llm = LLM(s)
        for p in llm.providers:
            reply = p.complete("Reply with exactly: pong", "ping", max_tokens=16, json_mode=False)
            line(
                "ok" if reply else "!!",
                f"{p.name} ({p.model}) live call: {'answered' if reply else 'FAILED (check key, model name, quota)'}",
            )
            ok = ok and bool(reply)
    return 0 if ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="agentshield")
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve", help="run the API server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    doc = sub.add_parser(
        "doctor", help="check configuration: database, auth, LLM providers (no secrets printed)"
    )
    doc.add_argument(
        "--live",
        action="store_true",
        help="make one real, tiny call to each configured LLM provider",
    )
    sub.add_parser("demo", help="run the scripted end-to-end scenario and print the transcript")
    rt = sub.add_parser("redteam", help="run a red-team campaign and print the summary")
    rt.add_argument("--cases", type=int, default=300)
    args = parser.parse_args()

    if args.cmd == "serve":
        import uvicorn

        uvicorn.run("agentshield.main:app", host=args.host, port=args.port, reload=args.reload)
    elif args.cmd == "doctor":
        raise SystemExit(doctor(live=args.live))
    elif args.cmd == "demo":
        from agentshield.demo.scenario import run

        print(json.dumps(run(build_container(get_settings())), indent=2, default=str))
    elif args.cmd == "redteam":
        from agentshield.modules.redteam.runner import run_campaign

        res = run_campaign(get_settings(), max_cases=args.cases)
        print(
            json.dumps(
                {
                    k: res[k]
                    for k in ("params", "summary", "ablations", "defended_by_rule", "breaches")
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
