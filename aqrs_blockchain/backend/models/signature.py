from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.database import Base

if TYPE_CHECKING:
    from backend.models.transaction import Transaction


class Signature(Base):
    __tablename__ = "signatures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    transaction_id: Mapped[str] = mapped_column(ForeignKey("transactions.id"), unique=True, nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(50), nullable=False)
    security_level: Mapped[int] = mapped_column(Integer, nullable=False)
    signature_hex: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    public_key_hex: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    canonical_payload: Mapped[str | None] = mapped_column(String, nullable=True)
    signature_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    signing_time_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    verification_time_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    verification_status: Mapped[str] = mapped_column(String(20), nullable=False, default="UNVERIFIED")
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    transaction: Mapped["Transaction"] = relationship(back_populates="signature", foreign_keys=[transaction_id])

    def __repr__(self) -> str:
        return f"Signature(id={self.id}, algorithm={self.algorithm!r}, valid={self.is_valid})"
