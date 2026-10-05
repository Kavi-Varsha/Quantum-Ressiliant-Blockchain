from __future__ import annotations

import json
import time
from typing import Any

from sqlalchemy.orm import Session

from backend.models.aqrs_decision import AQRSDecision
from backend.models.audit_log import AuditLog
from backend.models.signature import Signature
from backend.models.transaction import Transaction
from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5

_LEVEL_TO_ALGORITHM = {
    2: "ML-DSA-44",
    3: "ML-DSA-65",
    5: "ML-DSA-87",
}

_ALGORITHM_TO_LEVEL = {value: key for key, value in _LEVEL_TO_ALGORITHM.items()}

_DILITHIUM_CLASSES = {
    2: Dilithium2,
    3: Dilithium3,
    5: Dilithium5,
}


def generate_ml_dsa_keypair(level: int) -> tuple[bytes, bytes]:
    if level not in _DILITHIUM_CLASSES:
        raise ValueError(f"Unsupported ML-DSA level: {level}. Supported levels are 2, 3, and 5.")
    dilithium = _DILITHIUM_CLASSES[level]
    public_key, private_key = dilithium.keygen()
    return public_key, private_key


def canonical_transaction_payload(transaction: Transaction, decision: AQRSDecision | None = None) -> dict[str, Any]:
    risk_level = (
        decision.risk_level.value if decision and getattr(decision.risk_level, "value", None) else transaction.risk_level.value if transaction.risk_level else "LOW"
    )
    security_level = decision.security_level if decision else transaction.cryptographic_mode or "ML-DSA-44"
    algorithm = decision.algorithm if decision else transaction.cryptographic_mode or "ML-DSA-44"
    if decision is not None and decision.selected_security_level in _LEVEL_TO_ALGORITHM:
        security_level = _LEVEL_TO_ALGORITHM[decision.selected_security_level]
        algorithm = security_level
    return {
        "transaction_id": transaction.transaction_id,
        "sender_account_id": transaction.sender_account_id,
        "receiver_account_id": transaction.receiver_account_id,
        "amount": str(transaction.amount),
        "currency": transaction.currency,
        "created_at": transaction.created_at.isoformat() if transaction.created_at else None,
        "risk_level": risk_level,
        "security_level": security_level,
        "algorithm": algorithm,
        "status": transaction.status.value if getattr(transaction.status, "value", None) is not None else str(transaction.status),
    }


def _canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _get_transaction_by_id(db: Session, transaction_id: str) -> Transaction | None:
    txn = db.query(Transaction).filter_by(transaction_id=transaction_id).first()
    if txn is None:
        txn = db.get(Transaction, transaction_id)
    return txn


def _log_crypto_event(
    db: Session,
    *,
    user_id: str | None,
    event_type: str,
    status: str,
    message: str,
    transaction_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    try:
        db.add(
            AuditLog(
                user_id=user_id,
                transaction_id=transaction_id,
                event_type=event_type,
                status=status,
                message=message,
                metadata_=metadata or {},
            )
        )
    except Exception:
        pass


class CryptoSignatureService:
    @staticmethod
    def sign_transaction(db: Session, transaction_id: str) -> dict[str, Any]:
        txn = _get_transaction_by_id(db, transaction_id)
        if txn is None:
            raise ValueError("Transaction not found.")

        decision = txn.aqrs_decision
        if decision is None:
            decision = AQRSDecision(
                transaction_id=txn.id,
                risk_score=txn.risk_score or 0,
                risk_level=txn.risk_level or txn.risk_level,
                selected_security_level=int(txn.aqrs_level or 2),
                algorithm=txn.cryptographic_mode or "ML-DSA-44",
                security_level=txn.cryptographic_mode or "ML-DSA-44",
                decision_reason="Transaction was signed using server-side AQRS metadata.",
                aqrs_score=0,
            )
            db.add(decision)
            db.flush()

        level = int(decision.selected_security_level)
        algorithm = _LEVEL_TO_ALGORITHM.get(level, decision.algorithm or "ML-DSA-44")
        payload = canonical_transaction_payload(txn, decision)
        payload_bytes = _canonical_payload_bytes(payload)

        public_key, private_key = generate_ml_dsa_keypair(level)
        start = time.perf_counter()
        signature = _DILITHIUM_CLASSES[level].sign(private_key, payload_bytes)
        signing_time_ms = (time.perf_counter() - start) * 1000

        start = time.perf_counter()
        is_valid = _DILITHIUM_CLASSES[level].verify(public_key, payload_bytes, signature)
        verification_time_ms = (time.perf_counter() - start) * 1000

        if not is_valid:
            _log_crypto_event(
                db,
                user_id=None,
                event_type="CRYPTO_SIGNATURE_INVALID",
                status="failure",
                message="ML-DSA signature generation produced an invalid signature.",
                transaction_id=txn.id,
                metadata={"transaction_id": txn.transaction_id, "algorithm": algorithm, "security_level": level},
            )
            raise ValueError("Generated ML-DSA signature did not verify successfully.")

        signature_record = db.query(Signature).filter_by(transaction_id=txn.id).first()
        if signature_record is None:
            signature_record = Signature(transaction_id=txn.id, algorithm=algorithm, security_level=level)

        signature_record.algorithm = algorithm
        signature_record.security_level = level
        signature_record.signature_hex = signature.hex()
        signature_record.public_key_hex = public_key.hex()
        signature_record.signature_size_bytes = len(signature)
        signature_record.signing_time_ms = float(signing_time_ms)
        signature_record.verification_time_ms = float(verification_time_ms)
        signature_record.is_valid = True
        signature_record.canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        signature_record.verification_status = "VERIFIED"
        txn.signature_id = signature_record.id
        txn.cryptographic_mode = algorithm
        db.add(signature_record)
        db.add(txn)
        db.flush()

        _log_crypto_event(
            db,
            user_id=None,
            event_type="CRYPTO_SIGNATURE_CREATED",
            status="success",
            message="Transaction signed with ML-DSA",
            transaction_id=txn.id,
            metadata={
                "transaction_id": txn.transaction_id,
                "algorithm": algorithm,
                "security_level": level,
                "signature_size_bytes": len(signature),
                "signing_time_ms": round(signing_time_ms, 4),
                "verification_time_ms": round(verification_time_ms, 4),
            },
        )
        return {
            "transaction_id": txn.transaction_id,
            "algorithm": algorithm,
            "security_level": level,
            "signature_size_bytes": len(signature),
            "signing_time_ms": round(signing_time_ms, 4),
            "verification_time_ms": round(verification_time_ms, 4),
            "valid": True,
        }

    @staticmethod
    def verify_transaction_signature(db: Session, transaction_id: str) -> dict[str, Any]:
        return CryptoSignatureService.verify_canonical_payload(db, transaction_id, None)

    @staticmethod
    def verify_canonical_payload(db: Session, transaction_id: str, payload_override: dict[str, Any] | None) -> dict[str, Any]:
        txn = _get_transaction_by_id(db, transaction_id)
        if txn is None:
            raise ValueError("Transaction not found.")

        signature_record = db.query(Signature).filter_by(transaction_id=txn.id).first()
        if signature_record is None:
            return {"transaction_id": txn.transaction_id, "valid": False, "algorithm": None, "security_level": None, "signature_size_bytes": 0, "verification_time_ms": 0.0}

        payload = payload_override if payload_override is not None else canonical_transaction_payload(txn, txn.aqrs_decision)
        payload_bytes = _canonical_payload_bytes(payload)
        signature_bytes = bytes.fromhex(signature_record.signature_hex)
        public_key = bytes.fromhex(signature_record.public_key_hex)
        level = int(signature_record.security_level)
        algorithm = signature_record.algorithm

        start = time.perf_counter()
        is_valid = _DILITHIUM_CLASSES[level].verify(public_key, payload_bytes, signature_bytes)
        verification_time_ms = (time.perf_counter() - start) * 1000

        signature_record.is_valid = bool(is_valid)
        signature_record.verification_time_ms = float(verification_time_ms)
        signature_record.verification_status = "VERIFIED" if is_valid else "INVALID"
        db.add(signature_record)
        db.flush()

        if is_valid:
            _log_crypto_event(
                db,
                user_id=None,
                event_type="CRYPTO_SIGNATURE_VERIFIED",
                status="success",
                message="ML-DSA signature verified successfully.",
                transaction_id=txn.id,
                metadata={
                    "transaction_id": txn.transaction_id,
                    "algorithm": algorithm,
                    "security_level": level,
                    "signature_size_bytes": len(signature_bytes),
                    "verification_time_ms": round(verification_time_ms, 4),
                },
            )
        else:
            _log_crypto_event(
                db,
                user_id=None,
                event_type="CRYPTO_VERIFICATION_FAILED",
                status="failure",
                message="ML-DSA signature verification failed.",
                transaction_id=txn.id,
                metadata={
                    "transaction_id": txn.transaction_id,
                    "algorithm": algorithm,
                    "security_level": level,
                    "signature_size_bytes": len(signature_bytes),
                    "verification_time_ms": round(verification_time_ms, 4),
                },
            )

        return {
            "transaction_id": txn.transaction_id,
            "valid": bool(is_valid),
            "algorithm": algorithm,
            "security_level": level,
            "signature_size_bytes": len(signature_bytes),
            "verification_time_ms": round(verification_time_ms, 4),
        }


def sign_transaction(db: Session, transaction_id: str) -> dict[str, Any]:
    return CryptoSignatureService.sign_transaction(db, transaction_id)


def verify_transaction_signature(db: Session, transaction_id: str) -> dict[str, Any]:
    return CryptoSignatureService.verify_transaction_signature(db, transaction_id)


__all__ = [
    "CryptoSignatureService",
    "generate_ml_dsa_keypair",
    "canonical_transaction_payload",
    "sign_transaction",
    "verify_transaction_signature",
]
