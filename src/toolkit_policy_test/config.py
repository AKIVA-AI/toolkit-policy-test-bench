"""Configuration management for Policy Test Bench"""
import os
from pathlib import Path


class Config:
    """Configuration settings"""
    
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    STRICT_MODE: bool = os.getenv("STRICT_MODE", "true").lower() == "true"
    ENABLE_AUDIT_LOG: bool = os.getenv("ENABLE_AUDIT_LOG", "true").lower() == "true"
    OUTPUT_DIR: Path = Path(os.getenv("OUTPUT_DIR", "/app/results"))
    
    @classmethod
    def validate(cls) -> None:
        """Validate configuration"""
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if cls.LOG_LEVEL.upper() not in valid_log_levels:
            raise ValueError(f"LOG_LEVEL must be one of {valid_log_levels}")


Config.validate()

