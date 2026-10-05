from datetime import datetime, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from backend.database.database import DatabaseManager
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.aqrs_decision import AQRSDecision
from backend.models.audit_log import AuditLog
from backend.models.block import Block
from backend.models.experiment import Experiment, ExperimentResult
from backend.models.signature import Signature
from backend.models.transaction import Transaction, TransactionStatus, RiskLevel
from backend.models.user import User, UserRole


@pytest.fixture

def db_session():
    manager = DatabaseManager("sqlite:///:memory:")
    manager.create_all()
    session = manager.SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_create_user_and_unique_constraints(db_session):
    user = User(
        username="alice",
        email="alice@example.com",
        password_hash="hashed-secret",
        role=UserRole.CUSTOMER,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    with pytest.raises(IntegrityError):
        dup_email = User(
            username="alice2",
            email="alice@example.com",
            password_hash="hash",
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        db_session.add(dup_email)
        db_session.commit()
    db_session.rollback()

    with pytest.raises(IntegrityError):
        dup_username = User(
            username="alice",
            email="alice2@example.com",
            password_hash="hash",
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        db_session.add(dup_username)
        db_session.commit()
    db_session.rollback()


def test_create_account_and_relationships(db_session):
    user = User(
        username="bob",
        email="bob@example.com",
        password_hash="hashed-secret",
        role=UserRole.CUSTOMER,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    account = Account(
        user_id=user.id,
        account_number="ACCT-1001",
        account_type=AccountType.SAVINGS,
        balance="1200.00",
        currency="INR",
        status=AccountStatus.ACTIVE,
    )
    db_session.add(account)
    db_session.commit()

    fetched = db_session.get(Account, account.id)
    assert fetched is not None
    assert fetched.account_number == "ACCT-1001"
    assert fetched.user_id == user.id
    assert fetched.balance == Decimal("1200.00")

    with pytest.raises(IntegrityError):
        bad = Account(
            user_id=user.id,
            account_number="ACCT-1001",
            account_type=AccountType.CURRENT,
            balance="-50.00",
            currency="INR",
            status=AccountStatus.ACTIVE,
        )
        db_session.add(bad)
        db_session.commit()
    db_session.rollback()


def test_transaction_constraints_and_relationships(db_session):
    sender = User(username="sender", email="sender@example.com", password_hash="hash", role=UserRole.CUSTOMER, is_active=True)
    receiver = User(username="receiver", email="receiver@example.com", password_hash="hash", role=UserRole.CUSTOMER, is_active=True)
    db_session.add_all([sender, receiver])
    db_session.commit()

    acc1 = Account(user_id=sender.id, account_number="ACC-S1", account_type=AccountType.SAVINGS, balance="5000.00", currency="INR", status=AccountStatus.ACTIVE)
    acc2 = Account(user_id=receiver.id, account_number="ACC-R1", account_type=AccountType.CURRENT, balance="3000.00", currency="INR", status=AccountStatus.ACTIVE)
    db_session.add_all([acc1, acc2])
    db_session.commit()

    tx = Transaction(
        transaction_id="TX-001",
        sender_account_id=acc1.id,
        receiver_account_id=acc2.id,
        amount="150.00",
        currency="INR",
        description="Transfer test",
        status=TransactionStatus.SUCCESS,
        risk_level=RiskLevel.MEDIUM,
        risk_score="42.50",
        aqrs_level=3,
        cryptographic_mode="ML-DSA",
    )
    db_session.add(tx)
    db_session.commit()
    assert db_session.get(Transaction, tx.id).amount == Decimal("150.00")

    with pytest.raises(IntegrityError):
        bad_amt = Transaction(
            transaction_id="TX-002",
            sender_account_id=acc1.id,
            receiver_account_id=acc2.id,
            amount="0.00",
            currency="INR",
            description="Zero amount",
            status=TransactionStatus.PENDING,
            risk_level=RiskLevel.LOW,
            risk_score="10.00",
            aqrs_level=2,
            cryptographic_mode="ECDSA",
        )
        db_session.add(bad_amt)
        db_session.commit()
    db_session.rollback()

    with pytest.raises(IntegrityError):
        same = Transaction(
            transaction_id="TX-003",
            sender_account_id=acc1.id,
            receiver_account_id=acc1.id,
            amount="25.00",
            currency="INR",
            description="Self transfer",
            status=TransactionStatus.FAILED,
            risk_level=RiskLevel.LOW,
            risk_score="5.00",
            aqrs_level=2,
            cryptographic_mode="ECDSA",
        )
        db_session.add(same)
        db_session.commit()
    db_session.rollback()


def test_aqrs_decision_and_signature_metadata(db_session):
    user = User(username="charlie", email="charlie@example.com", password_hash="hash", role=UserRole.CUSTOMER, is_active=True)
    db_session.add(user)
    db_session.commit()

    sender = Account(user_id=user.id, account_number="ACC-CHARLIE-S", account_type=AccountType.SAVINGS, balance="2000.00", currency="INR", status=AccountStatus.ACTIVE)
    receiver = Account(user_id=user.id, account_number="ACC-CHARLIE-R", account_type=AccountType.CURRENT, balance="1500.00", currency="INR", status=AccountStatus.ACTIVE)
    db_session.add_all([sender, receiver])
    db_session.commit()

    tx = Transaction(
        transaction_id="TX-010",
        sender_account_id=sender.id,
        receiver_account_id=receiver.id,
        amount="25.00",
        currency="INR",
        description="Test",
        status=TransactionStatus.PENDING,
        risk_level=RiskLevel.HIGH,
        risk_score="85.00",
        aqrs_level=5,
        cryptographic_mode="ML-DSA",
    )
    db_session.add(tx)
    db_session.commit()

    decision = AQRSDecision(
        transaction_id=tx.id,
        risk_score="85.00",
        risk_level=RiskLevel.HIGH,
        selected_security_level=5,
        decision_reason="High-risk transaction requiring stronger security",
        aqrs_score="0.085",
    )
    db_session.add(decision)
    db_session.commit()

    signature = Signature(
        transaction_id=tx.id,
        algorithm="ML-DSA",
        security_level=5,
        signature_size_bytes=3309,
        signing_time_ms=71.57,
        verification_time_ms=79.82,
        is_valid=True,
    )
    db_session.add(signature)
    db_session.commit()

    assert db_session.get(AQRSDecision, decision.id).transaction_id == tx.id
    assert db_session.get(Signature, signature.id).transaction_id == tx.id


def test_block_and_audit_event_relationships(db_session):
    user = User(username="dana", email="dana@example.com", password_hash="hash", role=UserRole.CUSTOMER, is_active=True)
    db_session.add(user)
    db_session.commit()

    sender = Account(user_id=user.id, account_number="ACC-SENDER", account_type=AccountType.CURRENT, balance="1000.00", currency="INR", status=AccountStatus.ACTIVE)
    receiver = Account(user_id=user.id, account_number="ACC-RECEIVER", account_type=AccountType.SAVINGS, balance="1000.00", currency="INR", status=AccountStatus.ACTIVE)
    db_session.add_all([sender, receiver])
    db_session.commit()

    tx = Transaction(
        transaction_id="TX-020",
        sender_account_id=sender.id,
        receiver_account_id=receiver.id,
        amount="50.00",
        currency="INR",
        description="Audit test",
        status=TransactionStatus.SUCCESS,
        risk_level=RiskLevel.LOW,
        risk_score="8.00",
        aqrs_level=2,
        cryptographic_mode="ECDSA",
    )
    db_session.add(tx)
    db_session.commit()

    block = Block(
        block_number=1,
        previous_hash="genesis",
        block_hash="abc123",
        timestamp=datetime.now(timezone.utc),
        transaction_count=1,
        block_size_bytes=512,
    )
    db_session.add(block)
    db_session.commit()

    tx.block_id = block.id
    db_session.commit()

    audit = AuditLog(
        user_id=user.id,
        transaction_id=tx.id,
        event_type="TRANSFER_INITIATED",
        status="SUCCESS",
        message="Transaction created and saved",
        metadata_={"amount": "50.00", "currency": "INR"},
    )
    db_session.add(audit)
    db_session.commit()

    assert tx.block_id == block.id
    assert db_session.get(AuditLog, audit.id).transaction_id == tx.id


def test_experiment_and_result_models(db_session):
    experiment = Experiment(
        experiment_name="AQRS Benchmark Run",
        transaction_count=100,
        status="COMPLETED",
    )
    db_session.add(experiment)
    db_session.commit()

    result = ExperimentResult(
        experiment_id=experiment.id,
        mode="AQRS",
        average_signing_time_ms="68.113",
        average_verification_time_ms="74.85",
        average_signature_size_bytes="3295.0",
        throughput_tps="14.68",
        blockchain_size_bytes="42718",
        aqrs_score="0.0466",
    )
    db_session.add(result)
    db_session.commit()

    stored = db_session.get(ExperimentResult, result.id)
    assert stored.mode == "AQRS"
    assert stored.experiment_id == experiment.id


def test_complete_transaction_graph_load(db_session):
    user = User(username="erin", email="erin@example.com", password_hash="hash", role=UserRole.CUSTOMER, is_active=True)
    db_session.add(user)
    db_session.commit()

    sender = Account(user_id=user.id, account_number="ACC-ERIN-S", account_type=AccountType.SAVINGS, balance="5000.00", currency="INR", status=AccountStatus.ACTIVE)
    receiver = Account(user_id=user.id, account_number="ACC-ERIN-R", account_type=AccountType.CURRENT, balance="2000.00", currency="INR", status=AccountStatus.ACTIVE)
    db_session.add_all([sender, receiver])
    db_session.commit()

    tx = Transaction(
        transaction_id="TX-100",
        sender_account_id=sender.id,
        receiver_account_id=receiver.id,
        amount="125.50",
        currency="INR",
        description="Internal transfer",
        status=TransactionStatus.PROCESSING,
        risk_level=RiskLevel.MEDIUM,
        risk_score="55.00",
        aqrs_level=3,
        cryptographic_mode="ML-DSA",
    )
    db_session.add(tx)
    db_session.commit()

    decision = AQRSDecision(
        transaction_id=tx.id,
        risk_score="55.00",
        risk_level=RiskLevel.MEDIUM,
        selected_security_level=3,
        decision_reason="Medium-risk transaction",
        aqrs_score="0.041",
    )
    db_session.add(decision)
    db_session.commit()

    signature = Signature(
        transaction_id=tx.id,
        algorithm="ML-DSA",
        security_level=3,
        signature_size_bytes=3309,
        signing_time_ms=71.57,
        verification_time_ms=79.82,
        is_valid=True,
    )
    db_session.add(signature)
    db_session.commit()

    block = Block(
        block_number=7,
        previous_hash="hash-previous",
        block_hash="hash-current",
        timestamp=datetime.now(timezone.utc),
        transaction_count=1,
        block_size_bytes=1024,
    )
    db_session.add(block)
    db_session.commit()

    tx.block_id = block.id
    db_session.commit()

    audit = AuditLog(
        user_id=user.id,
        transaction_id=tx.id,
        event_type="AQRS_DECISION",
        status="SUCCESS",
        message="AQRS decision recorded",
        metadata_={"selected_level": 3},
    )
    db_session.add(audit)
    db_session.commit()

    loaded_tx = db_session.execute(select(Transaction).where(Transaction.id == tx.id)).scalar_one()
    assert loaded_tx.sender_account_id == sender.id
    assert loaded_tx.receiver_account_id == receiver.id
    assert loaded_tx.signature is not None
    assert loaded_tx.aqrs_decision is not None
    assert loaded_tx.block_id == block.id
    assert len(loaded_tx.audit_logs) == 1
