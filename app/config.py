"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Data store mode: "json" (local JSON files) or "mongodb"
    data_store: str = "json"  # Switch: "json" for dev, "mongodb" for prod
    json_data_dir: str = "data"  # Directory for JSON file storage

    # MongoDB (used when data_store == "mongodb")
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_database: str = "firewall_studio"

    # Encryption — local master key for field-level encryption (no cloud KMS)
    encryption_enabled: bool = False
    kms_provider: str = "local"
    # Local master key (96 bytes base64) — auto-generated on first run if empty
    local_master_key: str = ""

    # App
    environment: str = "development"
    log_level: str = "INFO"

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


settings = Settings()
