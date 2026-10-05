from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./pqbank.db")
DATABASE_ECHO = os.getenv("DATABASE_ECHO", "false").lower() in {"1", "true", "yes", "on"}

# keep the database file in the project root by default for local SQLite development
if DATABASE_URL.startswith("sqlite") and not DATABASE_URL.startswith("sqlite:///"):
    DATABASE_URL = f"sqlite:///{BASE_DIR / DATABASE_URL.replace('sqlite:///', '')}"

if DATABASE_URL.startswith("sqlite:///./"):
    DATABASE_URL = f"sqlite:///{(BASE_DIR / DATABASE_URL.replace('sqlite:///./', '')).resolve()}"

__all__ = ["BASE_DIR", "DATABASE_URL", "DATABASE_ECHO"]
