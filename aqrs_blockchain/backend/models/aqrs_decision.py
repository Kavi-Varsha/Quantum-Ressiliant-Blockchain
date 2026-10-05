from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, Integer, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.database import Base
from backend.models.transaction import RiskLevel

if TYPE_CHECKING:
    from backend.models.transaction import Transaction


class AQRSDecision(Base):
    __tablename__ = "aqrs_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    transaction_id: Mapped[str] = mapped_column(ForeignKey("transactions.id"), unique=True, nullable=False, index=True)
    risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False, default=Decimal("0.00"))
    risk_level: Mapped[RiskLevel] = mapped_column(SAEnum(RiskLevel), nullable=False)
    selected_security_level: Mapped[int] = mapped_column(Integer, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(50), nullable=False, default="ML-DSA-44")
    security_level: Mapped[str] = mapped_column(String(50), nullable=False, default="ML-DSA-44")
    decision_reason: Mapped[str] = mapped_column(String(255), nullable=False)
    aqrs_score: Mapped[Decimal] = mapped_column(Numeric(10, 4), nullable=False, default=Decimal("0.0000"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    transaction: Mapped["Transaction"] = relationship(back_populates="aqrs_decision", foreign_keys=[transaction_id])

    def __repr__(self) -> str:
        return f"AQRSDecision(id={self.id}, risk_level={self.risk_level.value}, level={self.selected_security_level})"
