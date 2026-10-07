from __future__ import annotations

import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from hashlib import sha256
from typing import Any, Dict, List

from flask import Flask, abort, g, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from flask_cors import CORS
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5


app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

from backend.database.database import SessionLocal, create_tables
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.aqrs_decision import AQRSDecision
from backend.models.audit_log import AuditLog
from backend.models.transaction import Transaction, TransactionStatus
from backend.models.user import User, UserRole
from backend.services import (
    AQRSDecisionService,
    AuthorizationError,
    CryptoSignatureService,
    InsufficientBalanceError,
    TransactionService,
    ValidationError,
    add_transaction_to_ledger,
    build_decision_for_amount,
    classify_transaction_risk,
    select_security_level,
)

create_tables()

with SessionLocal() as _startup_db:
    from backend.services.blockchain_service import ensure_genesis_block

    ensure_genesis_block(_startup_db)
    _startup_db.commit()


TRANSACTIONS: List[Dict[str, Any]] = []
BLOCKS: List[Dict[str, Any]] = []

ECDSA_SIGN_BASELINE_MS = 0.8
ECDSA_VERIFY_BASELINE_MS = 0.4
ECDSA_SIG_SIZE_BYTES = 71


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def classify_risk(amount: float) -> str:
    return classify_transaction_risk(amount).value


def select_dilithium_level(risk_level: str) -> int:
    return select_security_level(risk_level)["selected_security_level"]


def dilithium_engine(level: int):
    if level == 2:
        return Dilithium2
    if level == 3:
        return Dilithium3
    return Dilithium5


def generate_tx_id() -> str:
    return f"TX{len(TRANSACTIONS) + 1:03d}"


def build_message(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_aqrs_score(level: int | str, sign_ms: float, verify_ms: float, sig_size: int) -> float:
    if level == "ecdsa":
        return 1.0
    security_bits = {2: 128, 3: 192, 5: 256}
    sign_ratio = sign_ms / ECDSA_SIGN_BASELINE_MS
    verify_ratio = verify_ms / ECDSA_VERIFY_BASELINE_MS
    size_ratio = sig_size / ECDSA_SIG_SIZE_BYTES
    overhead = (sign_ratio + verify_ratio + size_ratio) / 3.0
    return (security_bits[level] / 128.0) / overhead


def maybe_add_block() -> int | None:
    if len(TRANSACTIONS) % 5 != 0:
        return None
    previous_hash = BLOCKS[-1]["hash"] if BLOCKS else "GENESIS"
    tx_ids = [tx["transaction_id"] for tx in TRANSACTIONS[-5:]]
    block_hash = sha256(("".join(tx_ids) + previous_hash).encode("utf-8")).hexdigest()
    block_number = len(BLOCKS) + 1
    block = {
        "block_number": block_number,
        "transaction_count": 5,
        "hash": block_hash,
        "previous_hash": previous_hash,
        "timestamp": utc_now(),
        "transactions": tx_ids,
    }
    BLOCKS.append(block)
    return block_number


@app.get("/")
def index() -> Any:
    return render_template("login.html", page="login")


@app.get("/login")
def login_page() -> Any:
    return render_template("login.html", page="login")


@app.get("/register")
def register_page() -> Any:
    return render_template("register.html", page="register")


@app.get("/dashboard")
def dashboard_page() -> Any:
    if _current_user_from_session() is None:
        return redirect(url_for("login_page"))
    return render_template("dashboard.html", page="dashboard")


@app.get("/transfer")
def transfer_page() -> Any:
    if _current_user_from_session() is None:
        return redirect(url_for("login_page"))
    return render_template("transfer.html", page="transfer")


@app.get("/transactions")
def transactions_page() -> Any:
    if _current_user_from_session() is None:
        return redirect(url_for("login_page"))
    return render_template("transactions.html", page="transactions")


@app.get("/transaction/<transaction_id>")
def transaction_details_page(transaction_id: str) -> Any:
    user = _current_user_from_session()
    if user is None:
        return redirect(url_for("login_page"))
    with SessionLocal() as db:
        if TransactionService.get_transaction_for_user(db, user.id, transaction_id) is None:
            abort(404)
    return render_template("transaction_details.html", page="transaction-details", transaction_id=transaction_id)


@app.get("/research")
def research_page() -> Any:
    return send_from_directory(".", "index.html")


@app.post("/api/transaction")
def api_transaction() -> Any:
    payload = request.get_json(silent=True) or {}
    sender = str(payload.get("sender", "")).strip() or "Unknown"
    receiver = str(payload.get("receiver", "")).strip() or "Unknown"
    amount = float(payload.get("amount", 0) or 0)
    mode = payload.get("mode", "aqrs")

    risk_level = classify_risk(amount)

    if mode == "aqrs":
        dilithium_level = select_dilithium_level(risk_level)
        engine = dilithium_engine(dilithium_level)
        pk, sk = engine.keygen()
        tx_id = generate_tx_id()
        tx_payload = {
            "transaction_id": tx_id,
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "risk_level": risk_level,
            "mode": mode,
            "dilithium_level": dilithium_level,
            "timestamp": utc_now(),
        }
        message = build_message(tx_payload)
        start = time.perf_counter()
        signature = engine.sign(sk, message.encode("utf-8"))
        signing_time_ms = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        is_valid = engine.verify(pk, message.encode("utf-8"), signature)
        verification_time_ms = (time.perf_counter() - start) * 1000
        signature_size = len(signature)
        public_key_hex = pk.hex()
        signature_hex = signature.hex()
        aqrs_score = compute_aqrs_score(dilithium_level, signing_time_ms, verification_time_ms, signature_size)
    elif mode == "ecdsa":
        dilithium_level = None
        key = ec.generate_private_key(ec.SECP256K1())
        tx_id = generate_tx_id()
        tx_payload = {
            "transaction_id": tx_id,
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "risk_level": risk_level,
            "mode": mode,
            "dilithium_level": None,
            "timestamp": utc_now(),
        }
        message = build_message(tx_payload)
        start = time.perf_counter()
        signature = key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        signing_time_ms = (time.perf_counter() - start) * 1000
        public_key = key.public_key()
        start = time.perf_counter()
        public_key.verify(signature, message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        verification_time_ms = (time.perf_counter() - start) * 1000
        signature_size = len(signature)
        public_key_hex = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
        signature_hex = signature.hex()
        aqrs_score = compute_aqrs_score("ecdsa", signing_time_ms, verification_time_ms, signature_size)
        is_valid = True
    else:
        dilithium_level = {"dil2": 2, "dil3": 3, "dil5": 5}.get(mode, 2)
        engine = dilithium_engine(dilithium_level)
        pk, sk = engine.keygen()
        tx_id = generate_tx_id()
        tx_payload = {
            "transaction_id": tx_id,
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "risk_level": risk_level,
            "mode": mode,
            "dilithium_level": dilithium_level,
            "timestamp": utc_now(),
        }
        message = build_message(tx_payload)
        start = time.perf_counter()
        signature = engine.sign(sk, message.encode("utf-8"))
        signing_time_ms = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        is_valid = engine.verify(pk, message.encode("utf-8"), signature)
        verification_time_ms = (time.perf_counter() - start) * 1000
        signature_size = len(signature)
        public_key_hex = pk.hex()
        signature_hex = signature.hex()
        aqrs_score = compute_aqrs_score(dilithium_level, signing_time_ms, verification_time_ms, signature_size)

    block_number = maybe_add_block()

    tx_record = {
        "transaction_id": tx_id,
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "risk_level": risk_level,
        "mode": mode,
        "dilithium_level": dilithium_level,
        "signing_time_ms": round(signing_time_ms, 2),
        "verification_time_ms": round(verification_time_ms, 2),
        "signature_size_bytes": signature_size,
        "signature_hex": signature_hex[:64],
        "public_key_hex": public_key_hex[:64],
        "is_valid": bool(is_valid),
        "block_number": block_number,
        "timestamp": utc_now(),
        "aqrs_score": round(aqrs_score, 4),
    }
    TRANSACTIONS.append(tx_record)

    return jsonify(tx_record)


@app.post("/api/sign-message")
def api_sign_message() -> Any:
    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message", ""))
    mode = payload.get("mode", "ecdsa")

    if mode == "ecdsa":
        key = ec.generate_private_key(ec.SECP256K1())
        start = time.perf_counter()
        signature = key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        signing_time_ms = (time.perf_counter() - start) * 1000
        public_key = key.public_key()
        public_key_hex = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
        return jsonify(
            {
                "signature_hex": signature.hex(),
                "public_key_hex": public_key_hex,
                "signing_time_ms": round(signing_time_ms, 2),
                "key_size_bytes": 64,
                "signature_size_bytes": len(signature),
            }
        )

    level = select_dilithium_level("MEDIUM")
    engine = dilithium_engine(level)
    pk, sk = engine.keygen()
    start = time.perf_counter()
    signature = engine.sign(sk, message.encode("utf-8"))
    signing_time_ms = (time.perf_counter() - start) * 1000

    return jsonify(
        {
            "signature_hex": signature.hex(),
            "public_key_hex": pk.hex(),
            "signing_time_ms": round(signing_time_ms, 2),
            "key_size_bytes": len(pk),
            "signature_size_bytes": len(signature),
        }
    )


@app.post("/api/verify-message")
def api_verify_message() -> Any:
    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message", ""))
    signature_hex = str(payload.get("signature_hex", ""))
    public_key_hex = str(payload.get("public_key_hex", ""))
    mode = payload.get("mode", "ecdsa")

    try:
        signature = bytes.fromhex(signature_hex)
        public_key_bytes = bytes.fromhex(public_key_hex)
    except ValueError:
        return jsonify({"is_valid": False, "verification_time_ms": 0.0})

    if mode == "ecdsa":
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
            start = time.perf_counter()
            public_key.verify(signature, message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
            verification_time_ms = (time.perf_counter() - start) * 1000
            return jsonify({"is_valid": True, "verification_time_ms": round(verification_time_ms, 2)})
        except Exception:
            return jsonify({"is_valid": False, "verification_time_ms": 0.0})

    level = select_dilithium_level("MEDIUM")
    engine = dilithium_engine(level)
    start = time.perf_counter()
    is_valid = engine.verify(public_key_bytes, message.encode("utf-8"), signature)
    verification_time_ms = (time.perf_counter() - start) * 1000
    return jsonify({"is_valid": bool(is_valid), "verification_time_ms": round(verification_time_ms, 2)})


def _serialize_user(user: User | None) -> Dict[str, Any] | None:
    if user is None:
        return None
    return {
        "id": user.id,
        "name": user.name,
        "username": user.username,
        "email": user.email,
        "role": user.role.value if isinstance(user.role, UserRole) else str(user.role),
        "is_active": user.is_active,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }


def _log_audit_event(
    user_id: str | None,
    event_type: str,
    status: str,
    message: str,
    *,
    metadata: Dict[str, Any] | None = None,
    transaction_id: str | None = None,
) -> None:
    try:
        with SessionLocal() as db:
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
            db.commit()
    except Exception:
        pass


def _current_user_from_session() -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            return None
        return user


def require_auth(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = _current_user_from_session()
        if user is None:
            _log_audit_event(None, "unauthorized_access", "failure", "Authentication required")
            return jsonify({"error": "Authentication required."}), 401
        g.current_user = user
        return view_func(*args, **kwargs)

    return wrapper


def require_role(*allowed_roles: str):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None) or _current_user_from_session()
            if user is None:
                _log_audit_event(None, "unauthorized_access", "failure", "Authentication required for protected route")
                return jsonify({"error": "Authentication required."}), 401

            user_role = user.role.value if isinstance(user.role, UserRole) else str(user.role)
            if user_role not in allowed_roles:
                _log_audit_event(
                    user.id,
                    "forbidden_access",
                    "forbidden",
                    "User attempted access without required role",
                    metadata={"required_roles": list(allowed_roles), "user_role": user_role},
                )
                return jsonify({"error": "Permission denied."}), 403

            g.current_user = user
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


@app.get("/api/transactions")
@require_auth
def api_transactions() -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        transactions = TransactionService.get_transactions_for_user(db, user.id)
        serialized = []
        for tx in transactions:
            decision = tx.aqrs_decision
            if decision is None:
                decision_policy = build_decision_for_amount(tx.amount)
                security_level = decision_policy["security_level"]
                algorithm = decision_policy["algorithm"]
            else:
                security_level = decision.security_level
                algorithm = decision.algorithm
            serialized.append(
                {
                    "id": tx.id,
                    "transaction_id": tx.transaction_id,
                    "sender_account_id": tx.sender_account_id,
                    "receiver_account_id": tx.receiver_account_id,
                    "amount": str(tx.amount),
                    "currency": tx.currency,
                    "description": tx.description,
                    "status": tx.status.value if hasattr(tx.status, "value") else str(tx.status),
                    "risk_level": tx.risk_level.value if tx.risk_level else None,
                    "security_level": security_level,
                    "algorithm": algorithm,
                    "created_at": tx.created_at.isoformat() if tx.created_at else None,
                }
            )

    return jsonify({"transactions": serialized})


@app.post("/api/transactions")
@require_auth
def create_transaction() -> Any:
    user = getattr(g, "current_user")
    payload = request.get_json(silent=True) or {}
    sender_account_id = str(payload.get("sender_account_id") or "").strip()
    receiver_account_id = str(payload.get("receiver_account_id") or "").strip()
    raw_amount = payload.get("amount")

    if not sender_account_id or not receiver_account_id:
        return jsonify({"error": "Sender and receiver account IDs are required."}), 400

    try:
        amount = TransactionService.parse_amount(raw_amount)
    except ValidationError as exc:
        _log_audit_event(user.id, "TRANSACTION_REJECTED", "failure", str(exc), metadata={"sender_account_id": sender_account_id, "receiver_account_id": receiver_account_id, "amount": raw_amount})
        return jsonify({"error": str(exc)}), 400

    with SessionLocal() as db:
        sender = db.get(Account, sender_account_id)
        receiver = db.get(Account, receiver_account_id)

        if sender is None or receiver is None:
            missing = "sender" if sender is None else "receiver"
            _log_audit_event(user.id, "TRANSACTION_REJECTED", "failure", f"Missing {missing} account", metadata={"sender_account_id": sender_account_id, "receiver_account_id": receiver_account_id})
            return jsonify({"error": "Account not found."}), 404

        if sender.id == receiver.id:
            _log_audit_event(user.id, "TRANSACTION_REJECTED", "failure", "Sender and receiver cannot be the same account", metadata={"sender_account_id": sender.id, "receiver_account_id": receiver.id})
            return jsonify({"error": "Sender and receiver accounts must be different."}), 400

        if user.role != UserRole.ADMIN and sender.user_id != user.id:
            _log_audit_event(user.id, "TRANSACTION_REJECTED", "forbidden", "User attempted transfer from another user's account", metadata={"sender_account_id": sender.id, "receiver_account_id": receiver.id, "request_user_id": user.id})
            return jsonify({"error": "You can only transfer from your own account."}), 403

        try:
            TransactionService.validate_account_state(sender)
            TransactionService.validate_account_state(receiver)
            if amount > sender.balance:
                raise InsufficientBalanceError("Insufficient balance for transfer.")

            risk = classify_transaction_risk(amount)
            decision_policy = select_security_level(risk)

            sender.balance -= amount
            receiver.balance += amount
            txn = Transaction(
                transaction_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
                sender_account_id=sender.id,
                receiver_account_id=receiver.id,
                amount=amount,
                currency=sender.currency or receiver.currency or "INR",
                description=payload.get("description") or f"Transfer from {sender.account_number} to {receiver.account_number}",
                status=TransactionStatus.COMPLETED,
                risk_level=risk,
                risk_score=Decimal("0.00"),
                aqrs_level=decision_policy["selected_security_level"],
                cryptographic_mode=decision_policy["algorithm"],
            )
            db.add(txn)
            db.flush()

            decision = AQRSDecisionService.evaluate_transaction(txn)
            db.add(decision)
            db.flush()

            _log_audit_event(
                user.id,
                "AQRS_DECISION_CREATED",
                "success",
                decision.decision_reason,
                metadata={
                    "transaction_id": txn.transaction_id,
                    "risk_level": decision.risk_level.value,
                    "security_level": decision.security_level,
                    "algorithm": decision.algorithm,
                    "selected_security_level": decision.selected_security_level,
                },
                transaction_id=txn.id,
            )

            try:
                signature_result = CryptoSignatureService.sign_transaction(db, txn.id)
                verification_result = CryptoSignatureService.verify_transaction_signature(db, txn.id)
                if not verification_result["valid"]:
                    raise ValueError("Transaction signature verification failed.")
                ledger_block = add_transaction_to_ledger(db, txn.id, user_id=user.id)
            except Exception as exc:
                db.rollback()
                _log_audit_event(user.id, "CRYPTO_SIGNATURE_FAILED", "failure", str(exc), metadata={"transaction_id": txn.transaction_id, "algorithm": decision.algorithm, "security_level": decision.security_level}, transaction_id=txn.id)
                return jsonify({"error": "Transaction could not be signed securely."}), 409

            db.commit()
            db.refresh(txn)
            db.refresh(decision)

            response_payload = {
                "id": txn.id,
                "transaction_id": txn.transaction_id,
                "sender_account_id": txn.sender_account_id,
                "receiver_account_id": txn.receiver_account_id,
                "amount": str(txn.amount),
                "currency": txn.currency,
                "status": txn.status.value if hasattr(txn.status, "value") else str(txn.status),
                "description": txn.description,
                "risk_level": txn.risk_level.value if txn.risk_level else None,
                "security_level": decision.security_level,
                "algorithm": decision.algorithm,
                "signature_available": True,
                "signature_size_bytes": signature_result.get("signature_size_bytes", 0),
                "block_number": ledger_block.block_number,
                "block_hash": ledger_block.block_hash,
                "created_at": txn.created_at.isoformat() if txn.created_at else None,
            }
            _log_audit_event(user.id, "TRANSACTION_CREATED", "success", "Transfer completed successfully", metadata={"transaction_id": txn.id, "sender_account_id": sender.id, "receiver_account_id": receiver.id, "amount": str(amount), "risk_level": risk.value, "security_level": decision.security_level}, transaction_id=txn.id)
            return jsonify({"message": "Transaction completed successfully", "transaction": response_payload})
        except (ValidationError, InsufficientBalanceError, ValueError) as exc:
            db.rollback()
            _log_audit_event(user.id, "TRANSACTION_REJECTED", "failure", str(exc), metadata={"sender_account_id": sender.id, "receiver_account_id": receiver.id, "amount": str(amount)}, transaction_id=None)
            return jsonify({"error": str(exc)}), 400 if isinstance(exc, ValidationError) else 409


@app.get("/api/transactions/<transaction_id>")
@require_auth
def get_transaction_by_id(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        txn = TransactionService.get_transaction_for_user(db, user.id, transaction_id)
        if txn is None:
            if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
                txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
            if txn is None:
                return jsonify({"error": "Transaction not found or access denied."}), 403 if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST} else 404

        decision = txn.aqrs_decision or AQRSDecisionService.evaluate_transaction(txn)
        return jsonify(
            {
                "transaction": {
                    "id": txn.id,
                    "transaction_id": txn.transaction_id,
                    "sender_account_id": txn.sender_account_id,
                    "receiver_account_id": txn.receiver_account_id,
                    "amount": str(txn.amount),
                    "currency": txn.currency,
                    "description": txn.description,
                    "status": txn.status.value if hasattr(txn.status, "value") else str(txn.status),
                    "risk_level": txn.risk_level.value if txn.risk_level else None,
                    "security_level": decision.security_level,
                    "algorithm": decision.algorithm,
                    "created_at": txn.created_at.isoformat() if txn.created_at else None,
                }
            }
        )


@app.get("/api/transactions/<transaction_id>/security")
@require_auth
def get_transaction_security(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
        if txn is None:
            return jsonify({"error": "Transaction not found."}), 404

        if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
            user_account_ids = {row[0] for row in db.query(Account.id).filter_by(user_id=user.id).all()}
            if txn.sender_account_id not in user_account_ids and txn.receiver_account_id not in user_account_ids:
                _log_audit_event(user.id, "AQRS_DECISION_FORBIDDEN", "forbidden", "User attempted to access another customer's security decision", metadata={"transaction_id": txn.id, "request_user_id": user.id})
                return jsonify({"error": "Access denied."}), 403

        decision = txn.aqrs_decision or AQRSDecisionService.evaluate_transaction(txn)
        if txn.aqrs_decision is None and decision.transaction_id == txn.id:
            db.add(decision)
            db.commit()
            db.refresh(decision)

        signature = txn.signature
        signature_available = signature is not None and bool(signature.signature_hex)
        return jsonify(
            {
                "transaction_id": txn.transaction_id,
                "risk_level": txn.risk_level.value if txn.risk_level else None,
                "security_level": decision.security_level,
                "algorithm": decision.algorithm,
                "selected_security_level": decision.selected_security_level,
                "compatibility_name": {
                    2: "DIL2",
                    3: "DIL3",
                    5: "DIL5",
                }.get(decision.selected_security_level, "DIL2"),
                "decision_reason": decision.decision_reason,
                "aqrs_score": str(decision.aqrs_score),
                "signature_available": signature_available,
                "signature_size": signature.signature_size_bytes if signature else 0,
                "verification_status": signature.verification_status if signature else "UNSIGNED",
            }
        )


@app.post("/api/transactions/<transaction_id>/sign")
@require_auth
def sign_transaction_endpoint(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        txn = TransactionService.get_transaction_for_user(db, user.id, transaction_id)
        if txn is None:
            if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
                txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
            if txn is None:
                return jsonify({"error": "Transaction not found or access denied."}), 404

        try:
            result = CryptoSignatureService.sign_transaction(db, txn.id)
            db.commit()
            _log_audit_event(user.id, "CRYPTO_SIGNATURE_CREATED", "success", "Signed transaction using ML-DSA", metadata={"transaction_id": txn.transaction_id, "algorithm": result["algorithm"], "security_level": result["security_level"]}, transaction_id=txn.id)
            return jsonify(result)
        except Exception as exc:
            db.rollback()
            _log_audit_event(user.id, "CRYPTO_SIGNATURE_FAILED", "failure", str(exc), metadata={"transaction_id": txn.transaction_id}, transaction_id=txn.id)
            return jsonify({"error": str(exc)}), 409


@app.get("/api/transactions/<transaction_id>/verify")
@require_auth
def verify_transaction_endpoint(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        txn = TransactionService.get_transaction_for_user(db, user.id, transaction_id)
        if txn is None:
            if user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
                txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
            if txn is None:
                return jsonify({"error": "Transaction not found or access denied."}), 404

        result = CryptoSignatureService.verify_transaction_signature(db, txn.id)
        db.commit()
        return jsonify({
            "transaction_id": txn.transaction_id,
            "valid": result["valid"],
            "algorithm": result["algorithm"],
            "security_level": result["security_level"],
            "signature_size_bytes": result["signature_size_bytes"],
            "verification_time_ms": result["verification_time_ms"],
        })


def _serialize_block(block) -> Dict[str, Any]:
    return {
        "id": block.id,
        "block_index": block.block_number,
        "timestamp": block.timestamp.isoformat() if block.timestamp else None,
        "previous_hash": block.previous_hash,
        "block_hash": block.block_hash,
        "transaction_count": block.transaction_count,
        "block_size_bytes": block.block_size_bytes,
        "created_at": block.created_at.isoformat() if block.created_at else None,
        "transactions": [
            {
                "id": transaction.id,
                "transaction_id": transaction.transaction_id,
                "signature_id": transaction.signature.id if transaction.signature else None,
            }
            for transaction in block.transactions
        ],
    }


@app.get("/api/blockchain")
@require_auth
def get_blockchain() -> Any:
    user = getattr(g, "current_user")
    if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        return jsonify({"error": "Access denied."}), 403
    from backend.services.blockchain_service import get_chain, validate_chain

    with SessionLocal() as db:
        return jsonify({"blocks": [_serialize_block(block) for block in get_chain(db)], "validation": validate_chain(db)})


@app.get("/api/blockchain/validate")
@require_auth
def validate_blockchain() -> Any:
    user = getattr(g, "current_user")
    if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        return jsonify({"error": "Access denied."}), 403
    from backend.services.blockchain_service import validate_chain

    with SessionLocal() as db:
        result = validate_chain(db)
    return jsonify(result)


@app.get("/api/blockchain/blocks/<int:block_number>")
@require_auth
def get_block_by_number(block_number: int) -> Any:
    user = getattr(g, "current_user")
    if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        return jsonify({"error": "Access denied."}), 403
    from backend.services.blockchain_service import get_block, validate_block

    with SessionLocal() as db:
        block = get_block(db, block_number)
        if block is None:
            return jsonify({"error": "Block not found."}), 404
        return jsonify({"block": _serialize_block(block), "validation": validate_block(db, block)})


@app.get("/api/transactions/<transaction_id>/block")
@require_auth
def get_transaction_block(transaction_id: str) -> Any:
    user = getattr(g, "current_user")
    from backend.services.blockchain_service import get_transaction_block as find_transaction_block

    with SessionLocal() as db:
        txn = TransactionService.get_transaction_for_user(db, user.id, transaction_id)
        if txn is None and user.role in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
            txn = TransactionService.get_transaction_by_identifier(db, transaction_id)
        if txn is None:
            return jsonify({"error": "Transaction not found or access denied."}), 404
        block = find_transaction_block(db, txn.id)
        if block is None:
            return jsonify({"error": "Transaction is not included in the ledger."}), 404
        return jsonify({"block": _serialize_block(block)})


@app.get("/api/security/aqrs/decisions")
@require_auth
def get_all_aqrs_decisions():
    user = getattr(g, "current_user")
    if user.role not in {UserRole.ADMIN, UserRole.SECURITY_ANALYST}:
        _log_audit_event(user.id, "AQRS_DECISION_FORBIDDEN", "forbidden", "Customer attempted to access system AQRS decisions", metadata={"user_role": user.role.value})
        return jsonify({"error": "Access denied."}), 403

    with SessionLocal() as db:
        decisions = db.query(AQRSDecision).order_by(AQRSDecision.created_at.desc()).all()

    return jsonify(
        {
            "decisions": [
                {
                    "id": d.id,
                    "transaction_id": d.transaction_id,
                    "risk_level": d.risk_level.value,
                    "selected_security_level": d.selected_security_level,
                    "security_level": d.security_level,
                    "algorithm": d.algorithm,
                    "compatibility_name": {
                        2: "DIL2",
                        3: "DIL3",
                        5: "DIL5",
                    }.get(d.selected_security_level, "DIL2"),
                    "decision_reason": d.decision_reason,
                    "aqrs_score": str(d.aqrs_score),
                    "created_at": d.created_at.isoformat() if d.created_at else None,
                }
                for d in decisions
            ]
        }
    )


@app.get("/api/blocks")
def api_blocks() -> Any:
    return jsonify(BLOCKS)


@app.post("/api/auth/register")
def register_user():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    email = str(payload.get("email", "")).strip().lower()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    requested_role = str(payload.get("role", "")).strip().upper()

    if not name or not email or not password:
        return jsonify({"error": "Name, email, and password are required."}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "A valid email address is required."}), 400
    if not username:
        username = email.split("@", 1)[0]
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
        return jsonify({"error": "Password must include uppercase, lowercase, and numeric characters."}), 400
    if requested_role and requested_role not in {"CUSTOMER"}:
        return jsonify({"error": "Public registration creates CUSTOMER accounts only."}), 400

    with SessionLocal() as db:
        if db.query(User).filter(func.lower(User.email) == email).first() is not None:
            _log_audit_event(None, "registration_failed", "conflict", "Duplicate email registration attempt", metadata={"email": email})
            return jsonify({"error": "An account with this email already exists."}), 409
        if db.query(User).filter_by(username=username).first() is not None:
            _log_audit_event(None, "registration_failed", "conflict", "Duplicate username registration attempt", metadata={"username": username})
            return jsonify({"error": "This username is already taken."}), 409

        user = User(
            name=name,
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=UserRole.CUSTOMER,
            is_active=True,
        )
        try:
            db.add(user)
            db.flush()

            account_number = f"INR-{uuid.uuid4().hex[:12].upper()}"
            account = Account(
                user_id=user.id,
                account_number=account_number,
                account_type=AccountType.SAVINGS,
                balance=Decimal("10000.00"),
                currency="INR",
                status=AccountStatus.ACTIVE,
            )
            db.add(account)
            db.commit()
            db.refresh(user)
        except Exception:
            db.rollback()
            return jsonify({"error": "Registration could not be completed."}), 500

        _log_audit_event(user.id, "registration_success", "success", "User registered successfully", metadata={"username": username, "role": user.role.value, "account_number": account.account_number})
        return jsonify({"message": "User registered successfully.", "user": _serialize_user(user)}), 201


@app.post("/api/auth/login")
def login_user():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email", "")).strip().lower()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))

    if not password or (not email and not username):
        return jsonify({"error": "Email/username and password are required."}), 400

    with SessionLocal() as db:
        user = None
        if email:
            user = db.query(User).filter(func.lower(User.email) == email).first()
        if user is None and username:
            user = db.query(User).filter_by(username=username).first()

        if user is None or not check_password_hash(user.password_hash, password):
            _log_audit_event(None, "login_failed", "failure", "Failed login attempt", metadata={"email": email or username})
            return jsonify({"error": "Invalid credentials."}), 401
        if not user.is_active:
            _log_audit_event(user.id, "login_failed", "failure", "Inactive account login attempt", metadata={"email": user.email})
            return jsonify({"error": "This account is inactive."}), 401

        user.last_login = datetime.now(timezone.utc)
        db.add(user)
        db.commit()
        session.clear()
        session["user_id"] = user.id
        session["user_role"] = user.role.value

        _log_audit_event(user.id, "login_success", "success", "User logged in successfully", metadata={"username": user.username})
        return jsonify({"message": "Login successful.", "user": _serialize_user(user)})


@app.post("/api/auth/logout")
@require_auth
def logout_user():
    user = getattr(g, "current_user")
    _log_audit_event(user.id, "logout", "success", "User logged out", metadata={"username": user.username})
    session.clear()
    return jsonify({"message": "Logged out successfully."})


@app.get("/api/auth/me")
@require_auth
def current_user_profile():
    user = getattr(g, "current_user")
    return jsonify({"user": _serialize_user(user)})


@app.get("/api/admin/test")
@require_auth
@require_role(UserRole.ADMIN.value)
def admin_test_endpoint():
    user = getattr(g, "current_user")
    return jsonify({"message": "Admin access granted.", "user": _serialize_user(user)})


@app.get("/api/security/test")
@require_auth
@require_role(UserRole.SECURITY_ANALYST.value)
def security_test_endpoint():
    user = getattr(g, "current_user")
    return jsonify({"message": "Security access granted.", "user": _serialize_user(user)})


@app.get("/api/users/me/accounts")
@require_auth
def my_accounts():
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        accounts = db.query(Account).filter_by(user_id=user.id).all()
    return jsonify({"accounts": [{"id": acc.id, "account_number": acc.account_number, "account_type": acc.account_type.value if hasattr(acc.account_type, "value") else str(acc.account_type), "balance": str(acc.balance), "currency": acc.currency, "status": acc.status.value if hasattr(acc.status, "value") else str(acc.status)} for acc in accounts]})


@app.get("/api/accounts/<account_id>")
@require_auth
def get_account_by_id(account_id: str):
    user = getattr(g, "current_user")
    with SessionLocal() as db:
        account = db.get(Account, account_id)
        if account is None:
            return jsonify({"error": "Account not found."}), 404
        if user.role != UserRole.ADMIN and account.user_id != user.id:
            _log_audit_event(
                user.id,
                "forbidden_account_access",
                "forbidden",
                "User attempted access to another user's account",
                metadata={"account_id": account.id, "owner_user_id": account.user_id, "request_user_id": user.id},
            )
            return jsonify({"error": "Account access denied."}), 403

        return jsonify(
            {
                "account": {
                    "id": account.id,
                    "user_id": account.user_id,
                    "account_number": account.account_number,
                    "account_type": account.account_type.value,
                    "balance": str(account.balance),
                    "currency": account.currency,
                    "status": account.status.value,
                }
            }
        )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
