from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.database import Base

if TYPE_CHECKING:
    from backend.models.transaction import Transaction


class Experiment(Base):
    __tablename__ = "experiments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    experiment_name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    transaction_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="PENDING", nullable=False)

    results: Mapped[list["ExperimentResult"]] = relationship(back_populates="experiment", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"Experiment(id={self.id}, name={self.experiment_name!r}, tx_count={self.transaction_count})"


class ExperimentResult(Base):
    __tablename__ = "experiment_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    experiment_id: Mapped[str] = mapped_column(ForeignKey("experiments.id"), nullable=False, index=True)
    mode: Mapped[str] = mapped_column(String(50), nullable=False)
    average_signing_time_ms: Mapped[float] = mapped_column(Float, nullable=False)
    average_verification_time_ms: Mapped[float] = mapped_column(Float, nullable=False)
    average_signature_size_bytes: Mapped[float] = mapped_column(Float, nullable=False)
    throughput_tps: Mapped[float] = mapped_column(Float, nullable=False)
    blockchain_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    aqrs_score: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    experiment: Mapped["Experiment"] = relationship(back_populates="results")

    def __repr__(self) -> str:
        return f"ExperimentResult(id={self.id}, mode={self.mode!r}, aqrs={self.aqrs_score})"
