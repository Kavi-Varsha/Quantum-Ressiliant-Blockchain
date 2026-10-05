from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, Enum as SAEnum, ForeignKey, Integer, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.database import Base

if TYPE_CHECKING:
    from backend.models.aqrs_decision import AQRSDecision
    from backend.models.audit_log import AuditLog
    from backend.models.block import Block
    from backend.models.signature import Signature


class TransactionStatus(str, Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    SUCCESS = "COMPLETED"
    FAILED = "FAILED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Transaction(Base):
    __tablename__ = "transactions"
    __table_args__ = (
        CheckConstraint("amount > 0", name="ck_transactions_amount_positive"),
        CheckConstraint("sender_account_id != receiver_account_id", name="ck_transactions_different_accounts"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    transaction_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    sender_account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False, index=True)
    receiver_account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False, index=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(15, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(10), default="INR", nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[TransactionStatus] = mapped_column(SAEnum(TransactionStatus), default=TransactionStatus.PENDING, nullable=False)
    risk_level: Mapped[RiskLevel | None] = mapped_column(SAEnum(RiskLevel), nullable=True)
    risk_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2), nullable=True)
    aqrs_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cryptographic_mode: Mapped[str | None] = mapped_column(String(50), nullable=True)
    signature_id: Mapped[str | None] = mapped_column(String(36), nullable=True, unique=True)
    block_id: Mapped[str | None] = mapped_column(ForeignKey("blocks.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    sender_account: Mapped["Account"] = relationship(back_populates="transactions_sent", foreign_keys=[sender_account_id])
    receiver_account: Mapped["Account"] = relationship(back_populates="transactions_received", foreign_keys=[receiver_account_id])
    signature: Mapped["Signature | None"] = relationship(back_populates="transaction", foreign_keys="Signature.transaction_id", uselist=False)
    aqrs_decision: Mapped["AQRSDecision | None"] = relationship(back_populates="transaction", foreign_keys="AQRSDecision.transaction_id", uselist=False)
    block: Mapped["Block | None"] = relationship(back_populates="transactions")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="transaction")

    def __repr__(self) -> str:
        return f"Transaction(id={self.id}, transaction_id={self.transaction_id!r}, amount={self.amount})"
