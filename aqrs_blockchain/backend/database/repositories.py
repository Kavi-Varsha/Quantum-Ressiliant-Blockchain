from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.account import Account
from backend.models.aqrs_decision import AQRSDecision
from backend.models.audit_log import AuditLog
from backend.models.block import Block
from backend.models.experiment import Experiment, ExperimentResult
from backend.models.signature import Signature
from backend.models.transaction import Transaction
from backend.models.user import User

T = TypeVar("T")


class BaseRepository:
    def __init__(self, session: Session):
        self.session = session

    def add(self, obj: T) -> T:
        self.session.add(obj)
        self.session.commit()
        self.session.refresh(obj)
        return obj

    def get_by_id(self, model: type[T], obj_id: Any) -> T | None:
        return self.session.get(model, obj_id)

    def list_all(self, model: type[T]):
        return self.session.execute(select(model)).scalars().all()


class UserRepository(BaseRepository):
    def get_by_email(self, email: str) -> User | None:
        return self.session.execute(select(User).where(User.email == email)).scalar_one_or_none()

    def get_by_username(self, username: str) -> User | None:
        return self.session.execute(select(User).where(User.username == username)).scalar_one_or_none()


class AccountRepository(BaseRepository):
    def get_by_number(self, account_number: str) -> Account | None:
        return self.session.execute(select(Account).where(Account.account_number == account_number)).scalar_one_or_none()

    def get_by_user(self, user_id):
        return self.session.execute(select(Account).where(Account.user_id == user_id)).scalars().all()


class TransactionRepository(BaseRepository):
    def get_by_transaction_id(self, transaction_id: str) -> Transaction | None:
        return self.session.execute(select(Transaction).where(Transaction.transaction_id == transaction_id)).scalar_one_or_none()

    def get_by_sender(self, account_id):
        return self.session.execute(select(Transaction).where(Transaction.sender_account_id == account_id)).scalars().all()

    def get_by_receiver(self, account_id):
        return self.session.execute(select(Transaction).where(Transaction.receiver_account_id == account_id)).scalars().all()


class SignatureRepository(BaseRepository):
    def get_by_transaction(self, transaction_id):
        return self.session.execute(select(Signature).where(Signature.transaction_id == transaction_id)).scalar_one_or_none()


class AQRSRepository(BaseRepository):
    def get_for_transaction(self, transaction_id):
        return self.session.execute(select(AQRSDecision).where(AQRSDecision.transaction_id == transaction_id)).scalar_one_or_none()


class BlockRepository(BaseRepository):
    def get_by_number(self, block_number: int) -> Block | None:
        return self.session.execute(select(Block).where(Block.block_number == block_number)).scalar_one_or_none()

    def get_by_hash(self, block_hash: str) -> Block | None:
        return self.session.execute(select(Block).where(Block.block_hash == block_hash)).scalar_one_or_none()


class AuditLogRepository(BaseRepository):
    def get_for_transaction(self, transaction_id):
        return self.session.execute(select(AuditLog).where(AuditLog.transaction_id == transaction_id)).scalars().all()


class ExperimentRepository(BaseRepository):
    def get_by_name(self, name: str) -> Experiment | None:
        return self.session.execute(select(Experiment).where(Experiment.experiment_name == name)).scalar_one_or_none()


__all__ = [
    "BaseRepository",
    "UserRepository",
    "AccountRepository",
    "TransactionRepository",
    "SignatureRepository",
    "AQRSRepository",
    "BlockRepository",
    "AuditLogRepository",
    "ExperimentRepository",
]
