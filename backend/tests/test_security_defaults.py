"""Deployment safety: production mode, policy exposure, JWT permissions, four-eyes, rate limits."""
import time

import jwt
import pytest

from gateway import config

SECRET = "test-secret-that-is-at-least-32-bytes-long"
EMP = {"X-API-Key": "demo-employee-key"}
HR = {"X-API-Key": "demo-hr-key"}
ADMIN = {"X-API-Key": "demo-admin-key"}


@pytest.fixture
def env(monkeypatch):
    def set_(**kv):
        for k, v in kv.items():
            monkeypatch.setenv(k, v)
        config.get_settings.cache_clear()
    yield set_
    config.get_settings.cache_clear()


def test_demo_defaults_are_reported():
    probs = config.production_problems(config.get_settings())
    assert any("demo API keys" in p for p in probs) and any("TOKENIZATION_SECRET" in p for p in probs)


def test_prod_refuses_to_start_with_demo_keys(env):
    from fastapi.testclient import TestClient
    from gateway.main import app

    env(GATEWAY_ENV="prod")
    with pytest.raises(RuntimeError, match="refusing to start"):
        with TestClient(app):
            pass


def test_prod_settings_pass_validation(env):
    env(GATEWAY_ENV="prod", TOKENIZATION_SECRET="x" * 40,
        GATEWAY_API_KEYS='{"k-123": {"user_id": "svc", "role": "employee", "tenant": "acme"}}')
    assert config.production_problems(config.get_settings()) == []


def test_policy_redacted_for_non_admins(client):
    emp = client.get("/v1/policy", headers=EMP).json()
    assert emp["redacted"] and emp["thresholds"] == {} and list(emp["roles"]) == ["employee"]
    assert "delete_employee" not in emp["tools"] and "search_employees" in emp["tools"]
    assert "thresholds" in client.get("/v1/policy", headers=ADMIN).json() and "redacted" not in client.get("/v1/policy", headers=ADMIN).json()


def test_demo_scenarios_need_auth(client):
    assert client.get("/v1/demo/scenarios").status_code == 401
    assert client.get("/v1/demo/scenarios", headers=EMP).status_code == 200


def test_jwt_cannot_grant_itself_permissions(client):
    tok = jwt.encode({"sub": "mallory", "role": "employee", "permissions": ["*"], "exp": int(time.time()) + 60},
                     SECRET, algorithm="HS256")
    me = client.get("/v1/whoami", headers={"Authorization": f"Bearer {tok}"}).json()
    assert me["permissions"] == []


def test_self_approval_refused_and_stays_pending(client):
    r = client.post("/v1/tools/execute", headers=ADMIN, json={
        "tool": "delete_employee", "arguments": {"employee_id": "EMP-1004"}, "user_request": "delete EMP-1004"}).json()
    aid = r["approval_id"]
    assert client.post(f"/v1/approvals/{aid}/approve", headers=ADMIN).status_code == 403
    assert any(a["id"] == aid for a in client.get("/v1/approvals?status=pending", headers=ADMIN).json())


def test_rate_limit(client, env):
    env(RATE_LIMIT_PER_MIN="3")
    codes = [client.get("/v1/whoami", headers=EMP).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_open_session_endpoint(client):
    sid = client.post("/v1/sessions", headers=HR).json()["session_id"]
    assert sid.startswith("gs_")
    # another user presenting it is refused
    r = client.post("/v1/guard/prompt", headers=EMP, json={"text": "hello", "session_id": sid}).json()
    assert r["decision"] == "BLOCK"
