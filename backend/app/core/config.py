"""
Auditor Configuration Settings
Central management of API keys, storage directories, and operational parameters.
"""
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "Auditor ASM & Vulnerability Risk Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"

    # Database
    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///./auditor.db")
    SYNC_DATABASE_URL: str = Field(default="sqlite:///./auditor.db")

    # API Keys for External Threat Intelligence
    SHODAN_KEY: Optional[str] = Field(default=None)
    SECURITYTRAILS_KEY: Optional[str] = Field(default=None)
    OTX_KEY: Optional[str] = Field(default=None)
    VIRUSTOTAL_KEY: Optional[str] = Field(default=None)
    URLSCAN_KEY: Optional[str] = Field(default=None)
    NVD_KEY: Optional[str] = Field(default=None)
    # Scanner Settings
    REQUEST_TIMEOUT: int = Field(default=15)
    MAX_CONCURRENCY: int = Field(default=10)
    RATE_LIMIT_PER_SEC: float = Field(default=5.0)
    USER_AGENT: str = Field(default="Auditor-Security-Scanner/1.0 (+https://auditor-defense.local/bot)")

    # Scope & Safety Policies
    PASSIVE_ONLY_DEFAULT: bool = Field(default=True)

    # Financial Cost Analyzer Defaults
    DEFAULT_DEV_HOURLY_RATE: float = Field(default=85.0)
    DEFAULT_TESTER_HOURLY_RATE: float = Field(default=65.0)
    DEFAULT_CURRENCY: str = Field(default="USD")
    DEFAULT_ASSET_VALUE: float = Field(default=250000.0)
    DEFAULT_RECORDS_COUNT: int = Field(default=50000)

    # Storage Paths
    OUTPUT_DIR: str = Field(default="output")
    PLUGINS_DIR: str = Field(default="plugins")

    # Notification & Alert Integrations
    SMTP_HOST: Optional[str] = Field(default=None)
    SMTP_PORT: int = Field(default=587)
    SMTP_USER: Optional[str] = Field(default=None)
    SMTP_PASSWORD: Optional[str] = Field(default=None)
    SMTP_FROM: str = Field(default="alerts@auditor.local")
    SLACK_WEBHOOK_URL: Optional[str] = Field(default=None)
    TELEGRAM_BOT_TOKEN: Optional[str] = Field(default=None)
    TELEGRAM_CHAT_ID: Optional[str] = Field(default=None)
    ENCRYPTION_KEY: Optional[str] = Field(default=None)
    DEMO_MODE: bool = Field(default=True)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()
