"""
Module 1: Transaction Generator
Generates financial transactions with risk classification for the AQRS simulation.
"""

import uuid
import random
import json
import time


class Transaction:
    """Represents a financial transaction that will be signed and added to the blockchain."""

    def __init__(self, transaction_id: str, sender: str, receiver: str,
                 amount: float, timestamp: float):
        self.transaction_id = transaction_id
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.timestamp = timestamp
        self.risk_level = self._classify_risk(amount)
        self.data = json.dumps({
            "transaction_id": self.transaction_id,
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "risk_level": self.risk_level,
        }, sort_keys=True)

    def _classify_risk(self, amount: float) -> str:
        if amount < 1000:
            return "LOW"
        elif amount < 100000:
            return "MEDIUM"
        else:
            return "HIGH"

    def __repr__(self) -> str:
        return (f"Transaction(id={self.transaction_id[:8]}..., "
                f"amount={self.amount:.2f}, risk={self.risk_level})")


def _random_wallet() -> str:
    """Generate a random 40-character hex wallet address."""
    return ''.join(random.choices('0123456789abcdef', k=40))


def generate_transactions(n: int = 100) -> list:
    """
    Generate n Transaction objects with the following amount distribution:
      - 40% LOW:    INR 10 – 999
      - 40% MEDIUM: INR 1,000 – 99,999
      - 20% HIGH:   INR 1,00,000 – 1,00,00,000

    Returns a shuffled list of Transaction objects.
    """
    low_count = int(n * 0.4)
    medium_count = int(n * 0.4)
    high_count = n - low_count - medium_count  # remaining 20%

    amounts = []
    for _ in range(low_count):
        amounts.append(round(random.uniform(10.0, 999.99), 2))
    for _ in range(medium_count):
        amounts.append(round(random.uniform(1000.0, 99999.99), 2))
    for _ in range(high_count):
        amounts.append(round(random.uniform(100000.0, 10000000.0), 2))

    random.shuffle(amounts)

    transactions = []
    for amount in amounts:
        tx = Transaction(
            transaction_id=str(uuid.uuid4()),
            sender=_random_wallet(),
            receiver=_random_wallet(),
            amount=amount,
            timestamp=time.time(),
        )
        transactions.append(tx)

    return transactions
