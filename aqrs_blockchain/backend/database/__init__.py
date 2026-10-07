from backend.database.database import DatabaseManager, SessionLocal, create_tables, engine

_REPOSITORY_NAMES = {
    "UserRepository",
    "AccountRepository",
    "TransactionRepository",
    "SignatureRepository",
    "AQRSRepository",
    "BlockRepository",
    "AuditLogRepository",
    "ExperimentRepository",
}


def __getattr__(name):
    if name in _REPOSITORY_NAMES:
        from backend.database import repositories

        return getattr(repositories, name)
    if name == "seed_database":
        from backend.database.seed import seed_database

        return seed_database
    raise AttributeError(name)

__all__ = [
    "DatabaseManager",
    "SessionLocal",
    "engine",
    "create_tables",
    "seed_database",
    "UserRepository",
    "AccountRepository",
    "TransactionRepository",
    "SignatureRepository",
    "AQRSRepository",
    "BlockRepository",
    "AuditLogRepository",
    "ExperimentRepository",
]
