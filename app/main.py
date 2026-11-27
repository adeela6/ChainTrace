from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import FastAPI

from app.api.errors import register_error_handlers
from app.config import Settings
from app.repository.database import init_db, make_engine, make_session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    """Tests pass their own Settings (temp DB + temp storage folder)."""
    settings = settings or Settings()

    try:
        Fernet(settings.CHAINTRACE_MASTER_KEY.encode())
    except (ValueError, TypeError):
        raise RuntimeError(
            "CHAINTRACE_MASTER_KEY in .env is missing or not a valid Fernet key."
        ) from None

    Path(settings.STORAGE_DIR).mkdir(parents=True, exist_ok=True)

    engine = make_engine(settings.DATABASE_URL)
    init_db(engine)

    app = FastAPI(title="ChainTrace", version="1.0.0")
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)

    register_error_handlers(app)
    return app


def __getattr__(name: str):
    if name == "app":
        return create_app()
    raise AttributeError(name)