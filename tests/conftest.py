"""Shared pytest setup for every ChainTrace test.

Isolation: before any test imports the app, every setting is pointed at a
temporary folder with a throwaway master key, so tests never read or write
your real .env, chaintrace.db or storage/. Environment variables override
.env in pydantic-settings, and every Settings field is set here (a test in
tests/test_harness.py fails if A adds a setting without adding it below).
"""

import importlib.util
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

TEST_MASTER_KEY = Fernet.generate_key().decode()
TEST_ADMIN_PASSWORD = "test-admin-password-1"

_SESSION_DIR = Path(tempfile.mkdtemp(prefix="chaintrace-tests-"))


def build_test_env(base: Path) -> dict[str, str]:
    """Every setting from .env.example, with test-safe values rooted at `base`."""
    return {
        "CHAINTRACE_ENV": "test",
        "DATABASE_URL": f"sqlite:///{(base / 'chaintrace-test.db').as_posix()}",
        "STORAGE_DIR": str(base / "storage" / "evidence"),
        "CHAINTRACE_MASTER_KEY": TEST_MASTER_KEY,
        "SESSION_IDLE_MINUTES": "30",
        "SESSION_COOKIE_SECURE": "false",
        "MAX_UPLOAD_MB": "25",
        "ALLOWED_TYPES": "txt,log,csv,json,pdf,png,jpg,zip",
        "RATE_LIMIT_LOGIN": "5/minute",
        "RATE_LIMIT_TRANSFER": "10/minute",
        "RATE_LIMIT_UPLOAD": "10/minute",
        "SEED_ADMIN_USERNAME": "admin",
        "SEED_ADMIN_PASSWORD": TEST_ADMIN_PASSWORD,
        "LOG_LEVEL": "WARNING",
    }


# Runs when pytest loads this file, i.e. before any test module imports `app`.
os.environ.update(build_test_env(_SESSION_DIR))


def pytest_unconfigure(config):
    shutil.rmtree(_SESSION_DIR, ignore_errors=True)


def pytest_collection_modifyitems(config, items):
    """Copy evaluation_case marker data into the JUnit report for the results table."""
    for item in items:
        marker = item.get_closest_marker("evaluation_case")
        if marker is None:
            continue
        missing = {"id", "input", "expected"} - marker.kwargs.keys()
        if missing:
            raise pytest.UsageError(
                f"{item.nodeid}: evaluation_case needs id=, input= and expected= (missing {sorted(missing)})"
            )
        for key in ("id", "input", "expected"):
            item.user_properties.append((f"eval_{key}", marker.kwargs[key]))


@dataclass
class IsolatedEnv:
    base: Path
    db_path: Path
    storage_dir: Path
    env: dict[str, str]


@pytest.fixture
def test_env(tmp_path, monkeypatch) -> IsolatedEnv:
    """A fresh, empty database path and storage folder for one test."""
    env = build_test_env(tmp_path)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    storage = Path(env["STORAGE_DIR"])
    storage.mkdir(parents=True)
    return IsolatedEnv(base=tmp_path, db_path=tmp_path / "chaintrace-test.db", storage_dir=storage, env=env)


@pytest.fixture
def settings(test_env):
    from app.config import Settings

    return Settings()


@pytest.fixture
def client(test_env):
    """FastAPI TestClient on a fresh app. Skips until A pushes app.main.create_app()."""
    if importlib.util.find_spec("app.main") is None:
        pytest.skip("Waiting on A: app/main.py does not exist yet (test-plan Q11)")
    import app.main  # import errors inside A's code should fail loudly, not skip

    if not hasattr(app.main, "create_app"):
        pytest.skip("Waiting on A: app.main.create_app() (test-plan Q11)")

    from fastapi.testclient import TestClient

    with TestClient(app.main.create_app()) as test_client:
        yield test_client
