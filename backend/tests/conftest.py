import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
_tmp = tempfile.mkdtemp(prefix="gw-test-")
os.environ.update({
    "AUDIT_DB": os.path.join(_tmp, "audit.db"),
    "HR_DB": os.path.join(_tmp, "hr.db"),
    "ML_MODE": "heuristic",
    "INTENT_MODE": "heuristic",
    "FAIL_MODE": "strict",
    "GATEWAY_JWT_SECRET": "test-secret-that-is-at-least-32-bytes-long",
})

from gateway.config import get_settings  # noqa: E402

get_settings.cache_clear()

from gateway.models import Principal  # noqa: E402
from gateway.stages import conversation  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_sessions():
    conversation.store.clear()
    yield


@pytest.fixture
def employee():
    return Principal(user_id="alice", role="employee", tenant="acme")


@pytest.fixture
def hr():
    return Principal(user_id="harini", role="hr_manager", tenant="acme")


@pytest.fixture
def admin():
    return Principal(user_id="root-admin", role="security_admin", tenant="acme")


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from gateway.main import app
    from gateway.tools import hr_env

    with TestClient(app) as c:
        hr_env.reset()
        yield c


EMP = {"X-API-Key": "demo-employee-key"}
HR = {"X-API-Key": "demo-hr-key"}
ADMIN = {"X-API-Key": "demo-admin-key"}
