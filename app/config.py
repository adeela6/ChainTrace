from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    CHAINTRACE_ENV: str = "development"
    DATABASE_URL: str = "sqlite:///./chaintrace.db"
    STORAGE_DIR: str = "./storage/evidence"
    CHAINTRACE_MASTER_KEY: str = ""
    SESSION_IDLE_MINUTES: int = 30
    SESSION_COOKIE_SECURE: bool = False
    MAX_UPLOAD_MB: int = 25
    ALLOWED_TYPES: str = "txt,log,csv,json,pdf,png,jpg,zip"
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_TRANSFER: str = "10/minute"
    SEED_ADMIN_USERNAME: str = "admin"
    SEED_ADMIN_PASSWORD: str = ""
    LOG_LEVEL: str = "INFO"
