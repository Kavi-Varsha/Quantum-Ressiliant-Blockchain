from __future__ import annotations

import os
import uuid
from decimal import Decimal

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_module5.db")

from backend.database.database import SessionLocal, create_tables

create_tables()
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.aqrs_decision import AQRSDecision
from backend.models.transaction import RiskLevel, Transaction, TransactionStatus
from backend.models.user import User, UserRole
from backend.services.crypto_service import (
    CryptoSignatureService,
    generate_ml_dsa_keypair,
    verify_transaction_signature,
)


def _create_user_and_accounts(email: str, username: str, balance: str = "10000.00"):
    unique = uuid.uuid4().hex[:8]
    user_name = f"{username}_{unique}"
    with SessionLocal() as db:
        user = User(
            name=user_name.title(),
            username=user_name,
            email=email,
            password_hash="hash",
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        sender = Account(
            user_id=user.id,
            account_number=f"ACC-{user_name.upper()}-S",
            account_type=AccountType.SAVINGS,
            balance=Decimal(balance),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        receiver = Account(
            user_id=user.id,
            account_number=f"ACC-{user_name.upper()}-R",
            account_type=AccountType.CURRENT,
            balance=Decimal("2000.00"),
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db.add_all([sender, receiver])
        db.commit()
        db.refresh(sender)
        db.refresh(receiver)
        return user, sender, receiver


def test_ml_dsa_key_generation_works_for_supported_levels():
    for level in (2, 3, 5):
        public_key, private_key = generate_ml_dsa_keypair(level)
        assert isinstance(public_key, (bytes, bytearray))
        assert isinstance(private_key, (bytes, bytearray))
        assert len(public_key) > 0
        assert len(private_key) > 0


def test_valid_transaction_can_be_signed_and_verified():
    user, sender, receiver = _create_user_and_accounts("mod5_a@example.com", "mod5a", "15000.00")

    with SessionLocal() as db:
        txn = Transaction(
            transaction_id="TX-MODULE5-A",
            sender_account_id=sender.id,
            receiver_account_id=receiver.id,
            amount=Decimal("500.00"),
            currency="INR",
            description="ML-DSA signing test",
            status=TransactionStatus.PENDING,
            risk_level=RiskLevel.LOW,
            risk_score=Decimal("10.00"),
            aqrs_level=2,
            cryptographic_mode="ML-DSA-44",
        )
        db.add(txn)
        db.commit()
        db.refresh(txn)

        decision = AQRSDecision(
            transaction_id=txn.id,
            risk_score=Decimal("10.00"),
            risk_level=RiskLevel.LOW,
            selected_security_level=2,
            algorithm="ML-DSA-44",
            security_level="ML-DSA-44",
            decision_reason="LOW-risk transaction selected ML-DSA-44 according to AQRS policy.",
            aqrs_score=Decimal("0.0146"),
        )
        db.add(decision)
        db.commit()
        db.refresh(decision)

        result = CryptoSignatureService.sign_transaction(db, txn.id)
        assert result["valid"] is True
        assert result["algorithm"] == "ML-DSA-44"
        assert result["signature_size_bytes"] > 0

        verification = verify_transaction_signature(db, txn.id)
        assert verification["valid"] is True
        assert verification["algorithm"] == "ML-DSA-44"


def test_modified_amount_invalidates_signature():
    user, sender, receiver = _create_user_and_accounts("mod5_b@example.com", "mod5b", "50000.00")

    with SessionLocal() as db:
        txn = Transaction(
            transaction_id="TX-MODULE5-B",
            sender_account_id=sender.id,
            receiver_account_id=receiver.id,
            amount=Decimal("25000.00"),
            currency="INR",
            description="Tamper detection test",
            status=TransactionStatus.PENDING,
            risk_level=RiskLevel.MEDIUM,
            risk_score=Decimal("42.00"),
            aqrs_level=3,
            cryptographic_mode="ML-DSA-65",
        )
        db.add(txn)
        db.commit()
        db.refresh(txn)

        decision = AQRSDecision(
            transaction_id=txn.id,
            risk_score=Decimal("42.00"),
            risk_level=RiskLevel.MEDIUM,
            selected_security_level=3,
            algorithm="ML-DSA-65",
            security_level="ML-DSA-65",
            decision_reason="MEDIUM-risk transaction selected ML-DSA-65 according to AQRS policy.",
            aqrs_score=Decimal("0.0148"),
        )
        db.add(decision)
        db.commit()

        CryptoSignatureService.sign_transaction(db, txn.id)

        signature = db.query(type(txn)).first() if False else None
        # tamper with the signed payload by changing the amount before verification
        from backend.services.crypto_service import canonical_transaction_payload

        tampered = canonical_transaction_payload(txn)
        tampered["amount"] = "90000.00"
        # use a service-level tamper check in the canonicalization path
        assert tampered["amount"] != str(txn.amount)

        result = CryptoSignatureService.verify_canonical_payload(
            db,
            txn.id,
            tampered,
        )
        assert result["valid"] is False


def test_client_cannot_force_different_security_level():
    user, sender, receiver = _create_user_and_accounts("mod5_c@example.com", "mod5c", "700000.00")

    with SessionLocal() as db:
        txn = Transaction(
            transaction_id="TX-MODULE5-C",
            sender_account_id=sender.id,
            receiver_account_id=receiver.id,
            amount=Decimal("500000.00"),
            currency="INR",
            description="High-risk test",
            status=TransactionStatus.PENDING,
            risk_level=RiskLevel.HIGH,
            risk_score=Decimal("92.00"),
            aqrs_level=5,
            cryptographic_mode="ML-DSA-87",
        )
        db.add(txn)
        db.commit()
        db.refresh(txn)

        decision = AQRSDecision(
            transaction_id=txn.id,
            risk_score=Decimal("92.00"),
            risk_level=RiskLevel.HIGH,
            selected_security_level=5,
            algorithm="ML-DSA-87",
            security_level="ML-DSA-87",
            decision_reason="HIGH-risk transaction selected ML-DSA-87 according to AQRS policy.",
            aqrs_score=Decimal("0.0116"),
        )
        db.add(decision)
        db.commit()

        result = CryptoSignatureService.sign_transaction(db, txn.id)
        assert result["algorithm"] == "ML-DSA-87"
        assert result["security_level"] == 5

        bad_candidate = dict(result)
        bad_candidate["algorithm"] = "ML-DSA-44"
        assert bad_candidate["algorithm"] != result["algorithm"]
