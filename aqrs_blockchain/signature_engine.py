"""
Module 2: Signature Engine
Handles ECDSA and CRYSTALS-Dilithium (Levels 2, 3, 5) key generation,
signing, and verification with millisecond-precision timing.
"""

import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5

_DILITHIUM_CLASSES = {
    2: Dilithium2,
    3: Dilithium3,
    5: Dilithium5,
}


class SignatureEngine:
    """Provides key generation, signing, and verification for ECDSA and Dilithium."""

    # ──────────────────────────────────────────────
    # ECDSA (SECP256K1 + SHA-256)
    # ──────────────────────────────────────────────

    def generate_ecdsa_keypair(self):
        """Generate an ECDSA keypair on curve SECP256K1.

        Returns:
            (private_key, public_key) — cryptography library objects.
        """
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_ecdsa(self, private_key, data: str):
        """Sign data string with the given ECDSA private key.

        Args:
            private_key: ECDSA private key (cryptography library object).
            data: UTF-8 string to sign.

        Returns:
            (signature_bytes, signing_time_ms)
        """
        data_bytes = data.encode("utf-8")
        start = time.perf_counter()
        signature = private_key.sign(data_bytes, ec.ECDSA(hashes.SHA256()))
        elapsed_ms = (time.perf_counter() - start) * 1000
        return signature, elapsed_ms

    def verify_ecdsa(self, public_key, data: str, signature_bytes: bytes):
        """Verify an ECDSA signature.

        Args:
            public_key: ECDSA public key (cryptography library object).
            data: Original UTF-8 string that was signed.
            signature_bytes: Signature to verify.

        Returns:
            (is_valid: bool, verification_time_ms: float)
        """
        data_bytes = data.encode("utf-8")
        start = time.perf_counter()
        try:
            public_key.verify(signature_bytes, data_bytes, ec.ECDSA(hashes.SHA256()))
            is_valid = True
        except Exception:
            is_valid = False
        elapsed_ms = (time.perf_counter() - start) * 1000
        return is_valid, elapsed_ms

    # ──────────────────────────────────────────────
    # Dilithium (Levels 2, 3, 5)
    # ──────────────────────────────────────────────

    def generate_dilithium_keypair(self, level: int):
        """Generate a Dilithium keypair at the given NIST security level.

        Args:
            level: 2, 3, or 5 — corresponds to Dilithium2 / Dilithium3 / Dilithium5.

        Returns:
            (public_key_bytes, secret_key_bytes)
        """
        dil = self._get_dilithium(level)
        pk, sk = dil.keygen()
        return pk, sk

    def sign_dilithium(self, secret_key: bytes, data: str, level: int):
        """Sign data string with the given Dilithium secret key.

        Args:
            secret_key: Dilithium secret key bytes.
            data: UTF-8 string to sign.
            level: Dilithium security level (2, 3, or 5).

        Returns:
            (signature_bytes, signing_time_ms)
        """
        dil = self._get_dilithium(level)
        data_bytes = data.encode("utf-8")
        start = time.perf_counter()
        signature = dil.sign(secret_key, data_bytes)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return signature, elapsed_ms

    def verify_dilithium(self, public_key: bytes, data: str,
                         signature_bytes: bytes, level: int):
        """Verify a Dilithium signature.

        Args:
            public_key: Dilithium public key bytes.
            data: Original UTF-8 string that was signed.
            signature_bytes: Signature to verify.
            level: Dilithium security level (2, 3, or 5).

        Returns:
            (is_valid: bool, verification_time_ms: float)
        """
        dil = self._get_dilithium(level)
        data_bytes = data.encode("utf-8")
        start = time.perf_counter()
        try:
            is_valid = dil.verify(public_key, data_bytes, signature_bytes)
        except Exception:
            is_valid = False
        elapsed_ms = (time.perf_counter() - start) * 1000
        return is_valid, elapsed_ms

    # ──────────────────────────────────────────────
    # AQRS Selector — Novel Contribution
    # ──────────────────────────────────────────────

    def select_dilithium_level(self, risk_level: str) -> int:
        """Map a transaction's risk level to the appropriate Dilithium security level.

        This is the AQRS adaptive selector:
          LOW    → Dilithium2  (128-bit PQ security)
          MEDIUM → Dilithium3  (192-bit PQ security)
          HIGH   → Dilithium5  (256-bit PQ security)

        Args:
            risk_level: One of "LOW", "MEDIUM", "HIGH".

        Returns:
            Integer 2, 3, or 5.
        """
        mapping = {"LOW": 2, "MEDIUM": 3, "HIGH": 5}
        if risk_level not in mapping:
            raise ValueError(
                f"Unknown risk level '{risk_level}'. Expected LOW, MEDIUM, or HIGH."
            )
        return mapping[risk_level]

    # ──────────────────────────────────────────────
    # Internal helper
    # ──────────────────────────────────────────────

    @staticmethod
    def _get_dilithium(level: int):
        if level not in _DILITHIUM_CLASSES:
            raise ValueError(
                f"Invalid Dilithium level {level}. Must be one of 2, 3, or 5."
            )
        return _DILITHIUM_CLASSES[level]
