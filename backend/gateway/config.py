"""Runtime configuration, read from environment variables.

Every setting has a laptop-friendly default so `uvicorn gateway.main:app` works
with zero configuration. Heavy stages (DeBERTa, Presidio, Ollama) are opt-in.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/


def _env(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


def _env_bool(name: str, default: bool) -> bool:
    return _env(name, str(default)).lower() in {"1", "true", "yes", "on"}


DEFAULT_API_KEYS = {
    # Demo identities. Override with GATEWAY_API_KEYS in any real deployment.
    "demo-employee-key": {"user_id": "alice", "role": "employee", "tenant": "acme"},
    "demo-hr-key": {"user_id": "harini", "role": "hr_manager", "tenant": "acme"},
    "demo-admin-key": {"user_id": "root-admin", "role": "security_admin", "tenant": "acme"},
}


@dataclass(frozen=True)
class Settings:
    # dev | prod. prod refuses to start with demo keys or default secrets (see production_problems)
    env: str = "dev"
    # requests per minute per authenticated principal (0 = unlimited)
    rate_limit_per_min: int = 120
    # trust a JWT's `permissions` claim on top of the role? Off by default: the role decides.
    jwt_trust_permissions: bool = False
    # --- auth ---
    api_keys: dict = field(default_factory=lambda: DEFAULT_API_KEYS)
    jwt_secret: str = ""  # empty = JWT auth disabled
    jwt_algorithm: str = "HS256"

    # --- stages ---
    # ml_mode: off | heuristic | deberta
    ml_mode: str = "heuristic"
    ml_model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    ml_threshold: float = 0.85
    # intent_mode: off | heuristic | ollama
    intent_mode: str = "heuristic"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:1.5b"
    ollama_timeout_s: float = 20.0
    # pii_engine: regex | presidio  (regex always runs; presidio adds NER on top)
    pii_engine: str = "regex"
    # fail_mode: strict = any errored stage => REQUIRE_APPROVAL at minimum
    #            balanced = errored stage only escalates medium/high-risk requests
    fail_mode: str = "strict"
    # sensitive tool calls need a gateway-known session and the user's request; otherwise approval
    require_session: bool = True

    # --- data protection ---
    tokenization_secret: str = "change-me-in-production"
    internal_email_domains: tuple = ("acme.com", "acme.internal")
    confidential_markers: tuple = ("PROJECT-ORION", "ACME-CONFIDENTIAL", "BOARD-ONLY")

    # --- storage ---
    audit_db: str = str(BASE_DIR / "data" / "audit.db")
    hr_db: str = str(BASE_DIR / "data" / "hr_demo.db")
    docs_dir: str = str(BASE_DIR / "data" / "docs")
    policy_file: str = str(BASE_DIR / "gateway" / "policy" / "policies.yaml")

    # --- llm used by the demo secure-RAG endpoint ---
    rag_llm: str = "extractive"  # extractive | ollama

    cors_origins: tuple = ("http://localhost:5173", "http://localhost:3000", "http://localhost:8080")


@lru_cache
def get_settings() -> Settings:
    keys_raw = os.getenv("GATEWAY_API_KEYS")
    return Settings(
        env=_env("GATEWAY_ENV", "dev").lower(),
        rate_limit_per_min=int(_env("RATE_LIMIT_PER_MIN", "120")),
        jwt_trust_permissions=_env_bool("JWT_TRUST_PERMISSIONS", False),
        api_keys=json.loads(keys_raw) if keys_raw else DEFAULT_API_KEYS,
        jwt_secret=_env("GATEWAY_JWT_SECRET", ""),
        ml_mode=_env("ML_MODE", "heuristic").lower(),
        ml_model=_env("ML_MODEL", Settings.ml_model),
        ml_threshold=float(_env("ML_THRESHOLD", "0.85")),
        intent_mode=_env("INTENT_MODE", "heuristic").lower(),
        ollama_url=_env("OLLAMA_URL", Settings.ollama_url),
        ollama_model=_env("OLLAMA_MODEL", Settings.ollama_model),
        ollama_timeout_s=float(_env("OLLAMA_TIMEOUT_S", "20")),
        pii_engine=_env("PII_ENGINE", "regex").lower(),
        fail_mode=_env("FAIL_MODE", "strict").lower(),
        require_session=_env_bool("REQUIRE_SESSION", True),
        tokenization_secret=_env("TOKENIZATION_SECRET", Settings.tokenization_secret),
        audit_db=_env("AUDIT_DB", Settings.audit_db),
        hr_db=_env("HR_DB", Settings.hr_db),
        docs_dir=_env("DOCS_DIR", Settings.docs_dir),
        policy_file=_env("POLICY_FILE", Settings.policy_file),
        rag_llm=_env("RAG_LLM", "extractive").lower(),
        cors_origins=tuple(
            o.strip() for o in _env("CORS_ORIGINS", ",".join(Settings.cors_origins)).split(",") if o.strip()
        ),
    )


def production_problems(s: Settings) -> list[str]:
    """Settings that are fine for a laptop demo but unsafe in a real deployment."""
    problems = []
    if any(k in DEFAULT_API_KEYS for k in s.api_keys):
        problems.append("demo API keys are enabled (set GATEWAY_API_KEYS)")
    if s.tokenization_secret == Settings.tokenization_secret or len(s.tokenization_secret) < 32:
        problems.append("TOKENIZATION_SECRET is the default or shorter than 32 characters")
    if s.jwt_secret and len(s.jwt_secret) < 32:
        problems.append("GATEWAY_JWT_SECRET is shorter than 32 characters")
    if "*" in s.cors_origins:
        problems.append("CORS_ORIGINS allows any origin")
    if s.fail_mode != "strict":
        problems.append("FAIL_MODE is not strict")
    return problems
