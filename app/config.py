from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application configuration settings."""

    # Database
    database_url: str = "postgresql://postgres:password@localhost:5432/cyberrag"

    # Ollama LLM
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
