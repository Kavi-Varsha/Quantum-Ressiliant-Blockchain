"""
Module 5: AQRS Score Calculator
Computes the Adaptive Quantum-Readiness Score (AQRS) for each simulation mode.

Formula:
    normalized_sign_time   = mode_avg_sign_time   / ecdsa_avg_sign_time
    normalized_verify_time = mode_avg_verify_time / ecdsa_avg_verify_time
    normalized_sig_size    = mode_avg_sig_size     / ecdsa_avg_sig_size

    overhead = (norm_sign + norm_verify + norm_sig_size) / 3

    security_gain = mode_security_bits / ecdsa_security_bits

    AQRS_score = security_gain / overhead

ECDSA baseline is always 1.0 by definition.
Higher score = better security-to-overhead ratio.
"""

# Post-quantum security bit assignments (fixed values from the spec)
_SECURITY_BITS = {
    "ECDSA": 128,   # Classical only
    "DIL2":  128,   # NIST Level 2
    "DIL3":  192,   # NIST Level 3
    "DIL5":  256,   # NIST Level 5
}

# Per-level security bits used for AQRS weighted average
_LEVEL_SECURITY_BITS = {
    2: 128,
    3: 192,
    5: 256,
}


def compute_all_aqrs_scores(all_mode_results: dict) -> dict:
    """Compute the AQRS score for every simulated mode.

    Args:
        all_mode_results: Dict mapping mode names to their simulation result dicts
                          as returned by run_simulation().

    Returns:
        Dict mapping each mode name to its AQRS score (float).
        ECDSA baseline is always 1.0.
    """
    ecdsa = all_mode_results["ECDSA"]
    ecdsa_avg_sign   = ecdsa["average_signing_time_ms"]
    ecdsa_avg_verify = ecdsa["average_verification_time_ms"]
    ecdsa_avg_size   = ecdsa["average_signature_size_bytes"]
    ecdsa_security   = _SECURITY_BITS["ECDSA"]

    scores = {}

    for mode_name, results in all_mode_results.items():
        if mode_name == "ECDSA":
            scores["ECDSA"] = 1.0
            continue

        avg_sign   = results["average_signing_time_ms"]
        avg_verify = results["average_verification_time_ms"]
        avg_size   = results["average_signature_size_bytes"]

        # Determine effective security bits
        if mode_name == "AQRS":
            security_bits = _aqrs_weighted_security(results["transactions"])
        else:
            security_bits = _SECURITY_BITS.get(mode_name, 128)

        # Normalize each dimension relative to ECDSA baseline
        norm_sign   = avg_sign   / ecdsa_avg_sign   if ecdsa_avg_sign   > 0 else 1.0
        norm_verify = avg_verify / ecdsa_avg_verify if ecdsa_avg_verify > 0 else 1.0
        norm_size   = avg_size   / ecdsa_avg_size   if ecdsa_avg_size   > 0 else 1.0

        overhead      = (norm_sign + norm_verify + norm_size) / 3.0
        security_gain = security_bits / ecdsa_security
        aqrs_score    = security_gain / overhead if overhead > 0 else 0.0

        scores[mode_name] = round(aqrs_score, 4)

    return scores


def _aqrs_weighted_security(tx_records: list) -> float:
    """Compute the weighted-average security bits for AQRS adaptive mode.

    Weights are proportional to the number of transactions at each Dilithium level.
    """
    level_counts = {2: 0, 3: 0, 5: 0}
    for tx in tx_records:
        lvl = tx.get("dilithium_level_used")
        if lvl in level_counts:
            level_counts[lvl] += 1

    total = sum(level_counts.values())
    if total == 0:
        return 128  # fallback

    weighted = sum(
        (count / total) * _LEVEL_SECURITY_BITS[lvl]
        for lvl, count in level_counts.items()
    )
    return weighted
