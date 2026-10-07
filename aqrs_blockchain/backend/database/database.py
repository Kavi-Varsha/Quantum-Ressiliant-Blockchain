from __future__ import annotations

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.config import DATABASE_ECHO, DATABASE_URL


class Base(DeclarativeBase):
    pass

def _build_engine(url: str, echo: bool = False):
    return create_engine(url, echo=echo, future=True)


class DatabaseManager:
    def __init__(self, url: str | None = None, echo: bool | None = None):
        self.url = url or DATABASE_URL
        self.echo = DATABASE_ECHO if echo is None else echo
        self.engine = _build_engine(self.url, self.echo)
        self.SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False, future=True)

    def create_all(self):
        Base.metadata.create_all(bind=self.engine)

    def drop_all(self):
        Base.metadata.drop_all(bind=self.engine)

    def get_session(self) -> Session:
        return self.SessionLocal()


engine = DatabaseManager().engine
SessionLocal = DatabaseManager().SessionLocal


def _migrate_existing_sqlite_schema() -> None:
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        if "users" in tables:
            existing_columns = {column["name"] for column in inspector.get_columns("users")}
            if "name" not in existing_columns:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE users ADD COLUMN name VARCHAR(120) NOT NULL DEFAULT ''"))
            if "last_login" not in existing_columns:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE users ADD COLUMN last_login DATETIME"))

        if "aqrs_decisions" in tables:
            existing_columns = {column["name"] for column in inspector.get_columns("aqrs_decisions")}
            if "algorithm" not in existing_columns:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE aqrs_decisions ADD COLUMN algorithm VARCHAR(50) NOT NULL DEFAULT 'ML-DSA-44'"))
            if "security_level" not in existing_columns:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE aqrs_decisions ADD COLUMN security_level VARCHAR(50) NOT NULL DEFAULT 'ML-DSA-44'"))

        if "signatures" in tables:
            existing_columns = {column["name"] for column in inspector.get_columns("signatures")}
            if "signature_hex" not in existing_columns:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE signatures ADD COLUMN signature_hex TEXT NOT NULL DEFAULT ''"))
            if "public_key_hex" not in existing_columns:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE signatures ADD COLUMN public_key_hex TEXT NOT NULL DEFAULT ''"))
            if "canonical_payload" not in existing_columns:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE signatures ADD COLUMN canonical_payload TEXT"))
            if "verification_status" not in existing_columns:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE signatures ADD COLUMN verification_status VARCHAR(20) NOT NULL DEFAULT 'UNVERIFIED'"))
    except Exception:
        # SQLite and other DBs may require a different migration path, but the
        # app should continue to operate with the current schema if no migration is needed.
        pass


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)
    _migrate_existing_sqlite_schema()


__all__ = ["Base", "DatabaseManager", "SessionLocal", "create_tables", "engine"]
