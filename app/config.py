"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Data store mode: "json" (local JSON files) or "mongodb"
    data_store: str = "json"  # Switch: "json" for dev, "mongodb" for prod
    json_data_dir: str = "data"  # Directory for JSON file storage

    # MongoDB (used when data_store == "mongodb")
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_database: str = "firewall_studio"

    # Encryption — KMS provider config (AWS KMS example; swap for Azure/Vault)
    encryption_enabled: bool = False
    kms_provider: str = "local"  # "aws" | "azure" | "gcp" | "local"
    # Local master key (32 bytes base64) — only for dev; use KMS in prod
    local_master_key: str = ""
    # AWS KMS (when kms_provider == "aws")
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_kms_key_arn: str = ""
    aws_kms_region: str = "us-east-1"

    # App
    environment: str = "development"
    log_level: str = "INFO"

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


settings = Settings()
