"""
Module 4: Simulation Runner
Runs the full blockchain signing/verification simulation for one mode and
returns a structured results dictionary.

Modes:
  "ECDSA" — Classical ECDSA (SECP256K1 + SHA-256)
  "DIL2"  — Dilithium Level 2 for all transactions
  "DIL3"  — Dilithium Level 3 for all transactions
  "DIL5"  — Dilithium Level 5 for all transactions
  "AQRS"  — Adaptive: level chosen per-transaction by risk_level
"""

from blockchain import Blockchain
from signature_engine import SignatureEngine

_VALID_MODES = {"ECDSA", "DIL2", "DIL3", "DIL5", "AQRS"}
_MODE_LEVEL_MAP = {"DIL2": 2, "DIL3": 3, "DIL5": 5}


def run_simulation(mode: str, transactions: list) -> dict:
    """Run the full simulation for *mode* over the given transaction list.

    Args:
        mode: One of "ECDSA", "DIL2", "DIL3", "DIL5", "AQRS".
        transactions: List of Transaction objects (from transaction_generator).

    Returns:
        mode_results dict — see module docstring for field descriptions.
    """
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown mode '{mode}'. Must be one of {_VALID_MODES}.")

    engine = SignatureEngine()
    blockchain = Blockchain(max_transactions_per_block=10)
    tx_records: list = []

    if mode == "ECDSA":
        private_key, public_key = engine.generate_ecdsa_keypair()

        for tx in transactions:
            sig_bytes, sign_time = engine.sign_ecdsa(private_key, tx.data)
            is_valid, verify_time = engine.verify_ecdsa(public_key, tx.data, sig_bytes)

            signed_tx = _build_signed_tx(tx, mode, sig_bytes, level=None)
            blockchain.add_transaction(signed_tx)

            tx_records.append(_build_tx_record(
                tx, mode,
                dilithium_level=None,
                sign_time=sign_time,
                verify_time=verify_time,
                sig_bytes=sig_bytes,
                is_valid=is_valid,
            ))

    elif mode in _MODE_LEVEL_MAP:
        level = _MODE_LEVEL_MAP[mode]
        pk, sk = engine.generate_dilithium_keypair(level)

        for tx in transactions:
            sig_bytes, sign_time = engine.sign_dilithium(sk, tx.data, level)
            is_valid, verify_time = engine.verify_dilithium(pk, tx.data, sig_bytes, level)

            signed_tx = _build_signed_tx(tx, mode, sig_bytes, level=level)
            blockchain.add_transaction(signed_tx)

            tx_records.append(_build_tx_record(
                tx, mode,
                dilithium_level=level,
                sign_time=sign_time,
                verify_time=verify_time,
                sig_bytes=sig_bytes,
                is_valid=is_valid,
            ))

    elif mode == "AQRS":
        # Pre-generate all three keypairs ONCE before the transaction loop
        pk2, sk2 = engine.generate_dilithium_keypair(2)
        pk3, sk3 = engine.generate_dilithium_keypair(3)
        pk5, sk5 = engine.generate_dilithium_keypair(5)
        keypairs = {
            2: (pk2, sk2),
            3: (pk3, sk3),
            5: (pk5, sk5),
        }

        for tx in transactions:
            level = engine.select_dilithium_level(tx.risk_level)
            pk, sk = keypairs[level]

            sig_bytes, sign_time = engine.sign_dilithium(sk, tx.data, level)
            is_valid, verify_time = engine.verify_dilithium(pk, tx.data, sig_bytes, level)

            signed_tx = _build_signed_tx(tx, mode, sig_bytes, level=level)
            blockchain.add_transaction(signed_tx)

            tx_records.append(_build_tx_record(
                tx, mode,
                dilithium_level=level,
                sign_time=sign_time,
                verify_time=verify_time,
                sig_bytes=sig_bytes,
                is_valid=is_valid,
            ))

    # Mine any remaining pending transactions that didn't fill a full block
    if blockchain.pending_transactions:
        blockchain.mine_block()

    return _aggregate_results(mode, tx_records, blockchain)


# ──────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────

def _build_signed_tx(tx, mode: str, sig_bytes: bytes, level) -> dict:
    """Build a JSON-serializable dict representing a signed transaction for storage."""
    record = {
        "transaction_id": tx.transaction_id,
        "sender": tx.sender,
        "receiver": tx.receiver,
        "amount": tx.amount,
        "timestamp": tx.timestamp,
        "risk_level": tx.risk_level,
        "mode": mode,
        "signature": sig_bytes.hex(),          # bytes → hex string for JSON storage
        "signature_size_bytes": len(sig_bytes),
    }
    if level is not None:
        record["dilithium_level"] = level
    return record


def _build_tx_record(tx, mode: str, dilithium_level, sign_time: float,
                     verify_time: float, sig_bytes: bytes, is_valid: bool) -> dict:
    """Build the per-transaction metrics record."""
    return {
        "transaction_id": tx.transaction_id,
        "amount": tx.amount,
        "risk_level": tx.risk_level,
        "mode_used": mode,
        "dilithium_level_used": dilithium_level,
        "signing_time_ms": sign_time,
        "verification_time_ms": verify_time,
        "signature_size_bytes": len(sig_bytes),
        "is_valid": is_valid,
    }


def _aggregate_results(mode: str, tx_records: list, blockchain: Blockchain) -> dict:
    """Compute aggregate metrics from per-transaction records."""
    n = len(tx_records)

    total_sign_ms = sum(r["signing_time_ms"] for r in tx_records)
    total_verify_ms = sum(r["verification_time_ms"] for r in tx_records)
    total_sig_bytes = sum(r["signature_size_bytes"] for r in tx_records)
    total_chain_bytes = blockchain.get_total_chain_size_bytes()
    num_blocks = len(blockchain.chain)

    avg_sign_ms = total_sign_ms / n
    avg_verify_ms = total_verify_ms / n
    avg_sig_bytes = total_sig_bytes / n
    avg_block_bytes = total_chain_bytes / num_blocks if num_blocks > 0 else 0.0

    # Throughput: total transactions / total signing time in seconds
    throughput_tps = n / (total_sign_ms / 1000.0) if total_sign_ms > 0 else 0.0

    return {
        "mode": mode,
        "transactions": tx_records,
        "total_transactions": n,
        "total_chain_size_bytes": total_chain_bytes,
        "average_block_size_bytes": avg_block_bytes,
        "total_signing_time_ms": total_sign_ms,
        "total_verification_time_ms": total_verify_ms,
        "average_signing_time_ms": avg_sign_ms,
        "average_verification_time_ms": avg_verify_ms,
        "average_signature_size_bytes": avg_sig_bytes,
        "throughput_tps": throughput_tps,
    }
