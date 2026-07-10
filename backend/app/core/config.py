from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    app_name: str = "Cyber-LLM API"
    debug: bool = False
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://cyber:cyber@localhost:5432/cyber"
    redis_url: str = "redis://localhost:6379/0"
    qdrant_url: str = "http://localhost:6333"
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "cyber"
    minio_secret_key: str = "cyber_secret"
    inference_url: str = "http://localhost:8001"

    jwt_secret: str = "change_me_in_production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    embedding_model: str = "BAAI/bge-small-en-v1.5"
    max_code_length: int = 8192
    sandbox_timeout: int = 30
    max_requests_per_minute: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
