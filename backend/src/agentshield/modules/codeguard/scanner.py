"""Code & Config Guard: secure-coding checks for agent-written code, dependencies and agent configs."""

from __future__ import annotations

import ast
import json
import re
import sys
from typing import Any, Literal

from pydantic import BaseModel, Field

from agentshield.core.dlp import scan_text
from agentshield.core.models import RISK_ORDER, Risk
from agentshield.modules.phishing.scanner import _lev

POPULAR_PY = {
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "pydantic",
    "sqlalchemy",
    "pytest",
    "boto3",
    "urllib3",
    "setuptools",
    "pyyaml",
    "cryptography",
    "scipy",
    "matplotlib",
    "pillow",
    "beautifulsoup4",
    "httpx",
    "aiohttp",
    "uvicorn",
    "jinja2",
    "click",
    "anthropic",
    "openai",
    "langchain",
    "torch",
    "tensorflow",
    "scikit-learn",
    "redis",
    "celery",
    "psycopg2",
    "pymongo",
    "paramiko",
    "lxml",
    "tqdm",
    "rich",
    "typer",
}
POPULAR_NPM = {
    "react",
    "lodash",
    "express",
    "axios",
    "moment",
    "webpack",
    "typescript",
    "next",
    "vue",
    "angular",
    "jquery",
    "chalk",
    "commander",
    "dotenv",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "uuid",
    "zod",
    "tailwindcss",
    "vite",
    "socket.io",
    "mongoose",
    "redux",
    "rxjs",
    "debug",
    "yargs",
    "request",
}
# Names LLMs have been observed to invent ("slopsquatting"); registering them is a known attack.
KNOWN_HALLUCINATED = {
    "huggingface-cli",
    "flask-jwt-extended-pro",
    "python-openai",
    "requests-async",
    "fastapi-utils-pro",
}
STDLIB_HINT = set(sys.stdlib_module_names)


class CodeFinding(BaseModel):
    rule: str
    severity: Risk
    message: str
    line: int | None = None
    cwe: str | None = None
    fix: str = ""
    snippet: str = ""


class ScanReport(BaseModel):
    language: str
    findings: list[CodeFinding] = Field(default_factory=list)
    gate: Literal["pass", "warn", "fail"] = "pass"
    summary: dict[str, int] = Field(default_factory=dict)


_LINE_RULES: list[tuple[str, Risk, re.Pattern[str], str, str, str]] = [
    (
        "sql-string-building",
        Risk.HIGH,
        re.compile(r"""(execute|query)\s*\(\s*(f["']|["'][^"']*["']\s*(\+|%|\.format))""", re.I),
        "CWE-89",
        "SQL built by string formatting is injectable.",
        "Use parameterised queries (cursor.execute(sql, params)).",
    ),
    (
        "shell-true",
        Risk.HIGH,
        re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
        "CWE-78",
        "shell=True with dynamic input enables command injection.",
        "Pass an argument list and omit shell=True.",
    ),
    (
        "os-system",
        Risk.HIGH,
        re.compile(r"\bos\.(system|popen)\s*\("),
        "CWE-78",
        "os.system executes through a shell.",
        "Use subprocess.run([...], check=True).",
    ),
    (
        "eval-exec",
        Risk.HIGH,
        re.compile(r"(?<![\w.])(eval|exec)\s*\("),
        "CWE-95",
        "eval/exec of dynamic content is arbitrary code execution.",
        "Use ast.literal_eval or a dispatch table.",
    ),
    (
        "unsafe-deserialization",
        Risk.HIGH,
        re.compile(r"\b(pickle|marshal|dill)\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)"),
        "CWE-502",
        "Deserialising untrusted data can run code.",
        "Use JSON, or yaml.safe_load.",
    ),
    (
        "weak-hash",
        Risk.MEDIUM,
        re.compile(r"hashlib\.(md5|sha1)\s*\(|createHash\(['\"](md5|sha1)['\"]\)"),
        "CWE-327",
        "MD5/SHA-1 are broken for security use.",
        "Use SHA-256+, and argon2/bcrypt for passwords.",
    ),
    (
        "tls-verify-off",
        Risk.HIGH,
        re.compile(
            r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true"
        ),
        "CWE-295",
        "TLS certificate validation is disabled.",
        "Remove the override; trust the system CA store.",
    ),
    (
        "debug-enabled",
        Risk.MEDIUM,
        re.compile(r"\bdebug\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True"),
        "CWE-489",
        "Debug mode exposes internals in production.",
        "Drive debug from environment configuration.",
    ),
    (
        "js-innerhtml",
        Risk.MEDIUM,
        re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\("),
        "CWE-79",
        "Writing untrusted data to the DOM enables XSS.",
        "Use textContent or a sanitiser such as DOMPurify.",
    ),
    (
        "wildcard-cors",
        Risk.MEDIUM,
        re.compile(
            r"allow_origins\s*=\s*\[\s*[\"']\*[\"']|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*"
        ),
        "CWE-942",
        "Wildcard CORS lets any site call this API.",
        "Allow-list known origins.",
    ),
    (
        "path-traversal",
        Risk.MEDIUM,
        re.compile(r"open\(\s*(request|req|input)\b|os\.path\.join\([^)]*request"),
        "CWE-22",
        "User input flows into a file path.",
        "Normalise and confine paths to a base directory.",
    ),
]


def _scan_python_ast(code: str) -> list[CodeFinding]:
    out: list[CodeFinding] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ExceptHandler)
            and node.type is None
            and all(isinstance(n, ast.Pass) for n in node.body)
        ):
            out.append(
                CodeFinding(
                    rule="bare-except-pass",
                    severity=Risk.LOW,
                    line=node.lineno,
                    cwe="CWE-390",
                    message="Bare `except: pass` silently swallows errors, including security failures.",
                    fix="Catch specific exceptions and log them.",
                )
            )
        if isinstance(node, ast.Assert):
            out.append(
                CodeFinding(
                    rule="assert-for-auth",
                    severity=Risk.LOW,
                    line=node.lineno,
                    cwe="CWE-617",
                    message="assert is stripped under -O; never use it for access control or validation.",
                    fix="Raise an explicit exception.",
                )
            )
    return out


def scan_code(code: str, language: str = "python") -> ScanReport:
    findings: list[CodeFinding] = []
    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        for rule, sev, rx, cwe, msg, fix in _LINE_RULES:
            if rx.search(line):
                findings.append(
                    CodeFinding(
                        rule=rule,
                        severity=sev,
                        line=i,
                        cwe=cwe,
                        message=msg,
                        fix=fix,
                        snippet=line.strip()[:140],
                    )
                )
        for hit in scan_text(line):
            if hit.category == "secret":
                findings.append(
                    CodeFinding(
                        rule=f"hardcoded-{hit.kind}",
                        severity=Risk.CRITICAL,
                        line=i,
                        cwe="CWE-798",
                        message=f"Hard-coded credential ({hit.kind}).",
                        fix="Move to a secret manager / environment variable and rotate the exposed value.",
                        snippet=hit.sample,
                    )
                )
    if language == "python":
        findings += _scan_python_ast(code)
        findings += _dependency_findings(_python_imports(code), "python")
    elif language in {"javascript", "typescript"}:
        findings += _dependency_findings(
            set(re.findall(r"""(?:require\(|from\s+)['"]([@\w./-]+)['"]""", code)), "npm"
        )
    return _finish(language, findings)


def _python_imports(code: str) -> set[str]:
    names: set[str] = set()
    try:
        for node in ast.walk(ast.parse(code)):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names.add(node.module.split(".")[0])
    except SyntaxError:
        pass
    return names - STDLIB_HINT


def _dependency_findings(names: set[str], ecosystem: str) -> list[CodeFinding]:
    popular = POPULAR_PY if ecosystem == "python" else POPULAR_NPM
    out: list[CodeFinding] = []
    for raw in sorted(names):
        name = raw.lower().replace("_", "-")
        if raw.startswith(".") or name in popular:
            continue
        if name in KNOWN_HALLUCINATED:
            out.append(
                CodeFinding(
                    rule="hallucinated-package",
                    severity=Risk.HIGH,
                    cwe="CWE-1357",
                    message=f"'{raw}' is a package name LLMs commonly invent; attackers register these.",
                    fix="Verify the package exists, is maintained, and is the one you intend.",
                )
            )
            continue
        near = next((p for p in popular if p != name and _lev(name, p) <= 1 and len(p) >= 5), None)
        if near:
            out.append(
                CodeFinding(
                    rule="typosquat-suspect",
                    severity=Risk.HIGH,
                    cwe="CWE-1357",
                    message=f"'{raw}' is one edit away from the popular package '{near}'.",
                    fix=f"Did you mean '{near}'? Check the registry page before installing.",
                )
            )
    return out


def scan_requirements(text: str, ecosystem: Literal["python", "npm"] = "python") -> ScanReport:
    names: set[str] = set()
    if ecosystem == "npm":
        try:
            pkg = json.loads(text)
            names = set(pkg.get("dependencies", {})) | set(pkg.get("devDependencies", {}))
        except json.JSONDecodeError:
            pass
    else:
        for line in text.splitlines():
            line = line.split("#")[0].strip()
            if line and not line.startswith("-"):
                names.add(re.split(r"[<>=!~\[;\s]", line)[0])
    return _finish(ecosystem, _dependency_findings(names, ecosystem))


_CRITICAL_TOOLS = {
    "run_shell",
    "transfer_funds",
    "change_permissions",
    "delete_records",
    "shell",
    "bash",
}


def audit_agent_config(config: dict[str, Any]) -> ScanReport:
    """Audit an agent / MCP-style config for over-broad permissions."""
    findings: list[CodeFinding] = []
    tools = config.get("tools", [])
    for t in tools:
        name = t.get("name", "?") if isinstance(t, dict) else str(t)
        perms = (t.get("permissions", []) if isinstance(t, dict) else []) or []
        if "*" in perms or name == "*":
            findings.append(
                CodeFinding(
                    rule="wildcard-permission",
                    severity=Risk.HIGH,
                    cwe="CWE-250",
                    message=f"Tool '{name}' has wildcard permissions.",
                    fix="Enumerate the minimum scopes the task needs.",
                )
            )
        if name in _CRITICAL_TOOLS and not (
            t.get("requires_approval") if isinstance(t, dict) else False
        ):
            findings.append(
                CodeFinding(
                    rule="critical-tool-no-approval",
                    severity=Risk.HIGH,
                    cwe="CWE-862",
                    message=f"Critical tool '{name}' executes without human approval.",
                    fix="Set requires_approval: true or remove the tool.",
                )
            )
        if isinstance(t, dict) and t.get("sandbox") is False:
            findings.append(
                CodeFinding(
                    rule="unsandboxed-tool",
                    severity=Risk.MEDIUM,
                    cwe="CWE-653",
                    message=f"Tool '{name}' runs without a sandbox.",
                    fix="Run in a container / restricted profile.",
                )
            )
    if config.get("allowed_domains") in (["*"], "*", None) and any(
        (t.get("name") if isinstance(t, dict) else t) in {"fetch_url", "browser", "http"}
        for t in tools
    ):
        findings.append(
            CodeFinding(
                rule="open-egress",
                severity=Risk.MEDIUM,
                cwe="CWE-923",
                message="Network tools allow any destination, enabling data exfiltration.",
                fix="Set an allow-list of domains.",
            )
        )
    for hit in scan_text(json.dumps(config)):
        if hit.category == "secret":
            findings.append(
                CodeFinding(
                    rule=f"config-secret-{hit.kind}",
                    severity=Risk.CRITICAL,
                    cwe="CWE-798",
                    message="Secret embedded in agent configuration.",
                    fix="Reference a secret manager instead.",
                    snippet=hit.sample,
                )
            )
    if not config.get("audit_logging", False):
        findings.append(
            CodeFinding(
                rule="no-audit-logging",
                severity=Risk.LOW,
                cwe="CWE-778",
                message="Audit logging is not enabled for this agent.",
                fix="Route tool calls through the guard / enable audit_logging.",
            )
        )
    return _finish("agent-config", findings)


def _finish(language: str, findings: list[CodeFinding]) -> ScanReport:
    findings.sort(key=lambda f: -RISK_ORDER[f.severity])
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    gate: Literal["pass", "warn", "fail"] = (
        "fail"
        if counts.get(Risk.CRITICAL) or counts.get(Risk.HIGH)
        else "warn"
        if findings
        else "pass"
    )
    return ScanReport(language=language, findings=findings, gate=gate, summary=counts)
