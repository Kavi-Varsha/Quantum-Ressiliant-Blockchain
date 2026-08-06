"""
Module 3: Blockchain
Implements Block and Blockchain classes.
Blocks are SHA-256 chained; the chain auto-mines when a block is full.
"""

import hashlib
import json
import time


class Block:
    """A single block in the blockchain."""

    def __init__(self, block_index: int, transactions: list, previous_hash: str):
        self.block_index = block_index
        self.timestamp = time.time()
        self.transactions = transactions          # list of signed-tx dicts
        self.previous_hash = previous_hash

        # Hash is computed over all other fields
        self.block_hash = self._compute_hash()

        # Size measured after block_hash is known so the full dict is serialized
        self.block_size_bytes = len(
            json.dumps(self._to_dict(), sort_keys=True).encode("utf-8")
        )

    def _compute_hash(self) -> str:
        """SHA-256 of the canonical JSON representation (excluding block_hash itself)."""
        content = json.dumps(
            {
                "block_index": self.block_index,
                "timestamp": self.timestamp,
                "transactions": self.transactions,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _to_dict(self) -> dict:
        return {
            "block_index": self.block_index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "block_hash": self.block_hash,
        }

    def __repr__(self) -> str:
        return (
            f"Block(index={self.block_index}, "
            f"txs={len(self.transactions)}, "
            f"hash={self.block_hash[:10]}...)"
        )


class Blockchain:
    """A simple append-only blockchain that auto-mines full blocks."""

    def __init__(self, max_transactions_per_block: int = 10):
        self.max_transactions_per_block = max_transactions_per_block
        self.chain: list = []
        self.pending_transactions: list = []
        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        genesis = Block(
            block_index=0,
            transactions=[],
            previous_hash="0" * 64,
        )
        self.chain.append(genesis)

    def add_transaction(self, signed_tx: dict) -> None:
        """Add a signed transaction to the pending pool.

        Automatically mines a block when the pool reaches max_transactions_per_block.
        """
        self.pending_transactions.append(signed_tx)
        if len(self.pending_transactions) >= self.max_transactions_per_block:
            self.mine_block()

    def mine_block(self) -> None:
        """Seal the current pending transactions into a new block."""
        if not self.pending_transactions:
            return
        last_block = self.chain[-1]
        new_block = Block(
            block_index=len(self.chain),
            transactions=list(self.pending_transactions),
            previous_hash=last_block.block_hash,
        )
        self.chain.append(new_block)
        self.pending_transactions = []

    def get_total_chain_size_bytes(self) -> int:
        """Return the total byte size of all blocks in the chain."""
        return sum(block.block_size_bytes for block in self.chain)

    def __len__(self) -> int:
        return len(self.chain)

    def __repr__(self) -> str:
        return (
            f"Blockchain(blocks={len(self.chain)}, "
            f"pending={len(self.pending_transactions)}, "
            f"size={self.get_total_chain_size_bytes()} B)"
        )
