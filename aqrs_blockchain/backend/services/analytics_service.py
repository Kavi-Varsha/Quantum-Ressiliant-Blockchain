from __future__ import annotations

from decimal import Decimal
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models.account import Account
from backend.models.aqrs_decision import AQRSDecision
from backend.models.audit_log import AuditLog
from backend.models.block import Block
from backend.models.signature import Signature
from backend.models.transaction import RiskLevel, Transaction, TransactionStatus
from backend.models.user import User, UserRole
from backend.services.blockchain_service import get_chain, validate_chain


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _decimal_value(value: Any) -> str:
    return str(value if value is not None else Decimal("0"))


def get_risk_distribution(db: Session) -> dict[str, int]:
    counts = {level.value: 0 for level in RiskLevel}
    rows = db.query(Transaction.risk_level, func.count(Transaction.id)).group_by(Transaction.risk_level).all()
    for risk_level, count in rows:
        if risk_level is not None:
            counts[_enum_value(risk_level)] = int(count)
    return counts


def get_algorithm_usage(db: Session) -> dict[str, int]:
    counts = {"ML-DSA-44": 0, "ML-DSA-65": 0, "ML-DSA-87": 0}
    rows = db.query(Signature.algorithm, func.count(Signature.id)).group_by(Signature.algorithm).all()
    for algorithm, count in rows:
        if algorithm in counts:
            counts[algorithm] = int(count)
    return counts


def get_signature_statistics(db: Session) -> dict[str, Any]:
    total = db.query(func.count(Signature.id)).scalar() or 0
    verified = db.query(func.count(Signature.id)).filter(Signature.verification_status == "VERIFIED").scalar() or 0
    failed = db.query(func.count(Signature.id)).filter(Signature.verification_status == "INVALID").scalar() or 0
    averages = db.query(
        func.avg(Signature.signature_size_bytes),
        func.avg(Signature.signing_time_ms),
        func.avg(Signature.verification_time_ms),
    ).one()
    return {
        "total": int(total),
        "verified": int(verified),
        "failed": int(failed),
        "average_signature_size_bytes": round(float(averages[0] or 0), 4),
        "average_signing_time_ms": round(float(averages[1] or 0), 4),
        "average_verification_time_ms": round(float(averages[2] or 0), 4),
    }


def get_aqrs_analytics(db: Session) -> dict[str, Any]:
    counts = {level.value: 0 for level in RiskLevel}
    level_counts = {"2": 0, "3": 0, "5": 0}
    algorithm_counts = {"ML-DSA-44": 0, "ML-DSA-65": 0, "ML-DSA-87": 0}
    score_rows: list[dict[str, str]] = []
    for decision in db.query(AQRSDecision).order_by(AQRSDecision.created_at.desc()).limit(250).all():
        risk = _enum_value(decision.risk_level)
        counts[risk] = counts.get(risk, 0) + 1
        level_counts[str(decision.selected_security_level)] = level_counts.get(str(decision.selected_security_level), 0) + 1
        algorithm_counts[decision.algorithm] = algorithm_counts.get(decision.algorithm, 0) + 1
        score_rows.append({"transaction_id": decision.transaction.transaction_id if decision.transaction else None, "risk_level": risk, "selected_security_level": str(decision.selected_security_level), "algorithm": decision.algorithm, "aqrs_score": _decimal_value(decision.aqrs_score)})
    return {"risk_distribution": counts, "security_levels": level_counts, "algorithm_usage": algorithm_counts, "decisions": score_rows}


def _transaction_row(transaction: Transaction) -> dict[str, Any]:
    decision = transaction.aqrs_decision
    signature = transaction.signature
    return {
        "transaction_id": transaction.transaction_id,
        "sender_account_id": transaction.sender_account_id,
        "receiver_account_id": transaction.receiver_account_id,
        "amount": _decimal_value(transaction.amount),
        "currency": transaction.currency,
        "status": _enum_value(transaction.status),
        "risk_level": _enum_value(transaction.risk_level),
        "algorithm": signature.algorithm if signature else decision.algorithm if decision else transaction.cryptographic_mode,
        "verification_status": signature.verification_status if signature else "UNSIGNED",
        "block_number": transaction.block.block_number if transaction.block else None,
        "created_at": transaction.created_at.isoformat() if transaction.created_at else None,
    }


def get_admin_overview(db: Session) -> dict[str, Any]:
    chain = validate_chain(db)
    transaction_count = db.query(func.count(Transaction.id)).scalar() or 0
    completed_count = db.query(func.count(Transaction.id)).filter(Transaction.status == TransactionStatus.COMPLETED).scalar() or 0
    failed_count = db.query(func.count(Transaction.id)).filter(Transaction.status == TransactionStatus.FAILED).scalar() or 0
    value = db.query(func.coalesce(func.sum(Transaction.amount), 0)).scalar()
    return {
        "customers": int(db.query(func.count(User.id)).filter(User.role == UserRole.CUSTOMER).scalar() or 0),
        "users": int(db.query(func.count(User.id)).scalar() or 0),
        "accounts": int(db.query(func.count(Account.id)).scalar() or 0),
        "transactions": int(transaction_count),
        "transaction_value": _decimal_value(value),
        "completed_transactions": int(completed_count),
        "failed_transactions": int(failed_count),
        "blocks": int(db.query(func.count(Block.id)).scalar() or 0),
        "chain": chain,
    }


def get_users(db: Session) -> list[dict[str, Any]]:
    return [{"name": user.name, "username": user.username, "email": user.email, "role": _enum_value(user.role), "is_active": user.is_active, "created_at": user.created_at.isoformat() if user.created_at else None} for user in db.query(User).order_by(User.created_at.desc()).limit(500).all()]


def get_transactions(db: Session) -> list[dict[str, Any]]:
    return [_transaction_row(transaction) for transaction in db.query(Transaction).order_by(Transaction.created_at.desc()).limit(500).all()]


def get_blockchain_analytics(db: Session) -> dict[str, Any]:
    chain = validate_chain(db)
    blocks = []
    for block in get_chain(db):
        blocks.append({"block_number": block.block_number, "timestamp": block.timestamp.isoformat() if block.timestamp else None, "transaction_count": block.transaction_count, "block_hash": block.block_hash, "previous_hash": block.previous_hash, "valid": bool(validate_chain_for_block(db, block)), "transactions": [_transaction_row(transaction) for transaction in block.transactions]})
    return {"validation": chain, "blocks": blocks}


def validate_chain_for_block(db: Session, block: Block) -> bool:
    from backend.services.blockchain_service import validate_block

    return bool(validate_block(db, block)["valid"])


def get_audit_logs(db: Session, *, security_only: bool = False) -> list[dict[str, Any]]:
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if security_only:
        query = query.filter(AuditLog.event_type.in_({"login_failed", "unauthorized_access", "forbidden_access", "CRYPTO_VERIFICATION_FAILED", "CRYPTO_SIGNATURE_INVALID", "BLOCK_CREATED", "TRANSACTION_REJECTED"}))
    rows = []
    for log in query.limit(500).all():
        rows.append({"timestamp": log.created_at.isoformat() if log.created_at else None, "event_type": log.event_type, "status": log.status, "user": log.user.username if log.user else None, "transaction_id": log.transaction.transaction_id if log.transaction else None, "message": log.message})
    return rows


def get_security_overview(db: Session) -> dict[str, Any]:
    return {"transactions": get_admin_overview(db), "risk_distribution": get_risk_distribution(db), "algorithm_usage": get_algorithm_usage(db), "signatures": get_signature_statistics(db), "aqrs": get_aqrs_analytics(db), "blockchain": get_blockchain_analytics(db), "security_events": get_audit_logs(db, security_only=True)[:100]}


__all__ = ["get_admin_overview", "get_audit_logs", "get_aqrs_analytics", "get_algorithm_usage", "get_blockchain_analytics", "get_risk_distribution", "get_security_overview", "get_signature_statistics", "get_transactions", "get_users"]