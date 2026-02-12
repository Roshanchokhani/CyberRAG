import secrets
from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache


class Settings(BaseSettings):
    """Application configuration settings."""

    # Database (no default — must be set via .env)
    database_url: str

    # Ollama LLM
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Security
    api_key: str = ""
    environment: str = "development"

    # Rate limiting
    rate_limit: str = "30/minute"

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if "password" in v and "localhost" not in v:
            raise ValueError("Default credentials detected in DATABASE_URL. Set a secure password in .env")
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
