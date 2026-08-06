from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, List

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5


app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)


TRANSACTIONS: List[Dict[str, Any]] = []
BLOCKS: List[Dict[str, Any]] = []

ECDSA_SIGN_BASELINE_MS = 0.8
ECDSA_VERIFY_BASELINE_MS = 0.4
ECDSA_SIG_SIZE_BYTES = 71


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def classify_risk(amount: float) -> str:
    if amount < 1000:
        return "LOW"
    if amount < 100000:
        return "MEDIUM"
    return "HIGH"


def select_dilithium_level(risk_level: str) -> int:
    if risk_level == "LOW":
        return 2
    if risk_level == "MEDIUM":
        return 3
    return 5


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


@app.get("/api/transactions")
def api_transactions() -> Any:
    return jsonify(TRANSACTIONS)


@app.get("/api/blocks")
def api_blocks() -> Any:
    return jsonify(BLOCKS)


@app.get("/api/stats")
def api_stats() -> Any:
    total_transactions = len(TRANSACTIONS)
    total_blocks = len(BLOCKS)
    mode_breakdown: Dict[str, int] = {}
    avg_signing_times: Dict[str, float] = {}

    for tx in TRANSACTIONS:
        mode_breakdown[tx["mode"]] = mode_breakdown.get(tx["mode"], 0) + 1

    for mode in mode_breakdown.keys():
        values = [tx["signing_time_ms"] for tx in TRANSACTIONS if tx["mode"] == mode]
        avg_signing_times[mode] = round(sum(values) / len(values), 2) if values else 0.0

    return jsonify(
        {
            "total_transactions": total_transactions,
            "total_blocks": total_blocks,
            "mode_breakdown": mode_breakdown,
            "avg_signing_times": avg_signing_times,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
