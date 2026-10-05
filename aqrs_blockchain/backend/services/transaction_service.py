from __future__ import annotations

from decimal import Decimal, InvalidOperation

from sqlalchemy.orm import Session

from backend.models.account import Account, AccountStatus
from backend.models.transaction import Transaction, TransactionStatus


class ValidationError(ValueError):
    pass


class AuthorizationError(PermissionError):
    pass


class InsufficientBalanceError(ValueError):
    pass


class TransactionService:
    @staticmethod
    def parse_amount(raw_amount: object) -> Decimal:
        if raw_amount is None or str(raw_amount).strip() == "":
            raise ValidationError("Transaction amount is required.")
        try:
            amount = Decimal(str(raw_amount))
        except (InvalidOperation, ValueError) as exc:
            raise ValidationError("Transaction amount must be a valid decimal value.") from exc

        if amount <= 0:
            raise ValidationError("Transaction amount must be greater than zero.")
        return amount.quantize(Decimal("0.01"))

    @staticmethod
    def validate_account_state(account: Account) -> None:
        if account.status != AccountStatus.ACTIVE:
            raise ValidationError(f"Account {account.account_number} is not active.")

    @staticmethod
    def create_transfer(
        db: Session,
        *,
        sender: Account,
        receiver: Account,
        amount: Decimal,
        description: str | None = None,
    ) -> Transaction:
        if sender.id == receiver.id:
            raise ValidationError("Sender and receiver accounts must be different.")

        TransactionService.validate_account_state(sender)
        TransactionService.validate_account_state(receiver)

        if amount > sender.balance:
            raise InsufficientBalanceError("Insufficient balance for transfer.")

        sender.balance -= amount
        receiver.balance += amount

        transaction = Transaction(
            transaction_id=f"TX-{sender.account_number}-{receiver.account_number}-{abs(hash((sender.id, receiver.id, str(amount))))}",
            sender_account_id=sender.id,
            receiver_account_id=receiver.id,
            amount=amount,
            currency=sender.currency or receiver.currency or "INR",
            description=description or "Funds transfer",
            status=TransactionStatus.COMPLETED,
        )
        db.add(transaction)
        db.flush()
        return transaction

    @staticmethod
    def get_transactions_for_user(db: Session, user_id: str) -> list[Transaction]:
        from backend.models.account import Account

        user_account_ids = [row[0] for row in db.query(Account.id).filter_by(user_id=user_id).all()]
        if not user_account_ids:
            return []
        return (
            db.query(Transaction)
            .filter(
                (Transaction.sender_account_id.in_(user_account_ids))
                | (Transaction.receiver_account_id.in_(user_account_ids))
            )
            .order_by(Transaction.created_at.desc())
            .all()
        )

    @staticmethod
    def get_transaction_by_identifier(db: Session, identifier: str) -> Transaction | None:
        return (
            db.query(Transaction)
            .filter((Transaction.id == identifier) | (Transaction.transaction_id == identifier))
            .one_or_none()
        )

    @staticmethod
    def get_transaction_for_user(db: Session, user_id: str, transaction_id: str) -> Transaction | None:
        from backend.services.account_service import AccountService

        tx = TransactionService.get_transaction_by_identifier(db, transaction_id)
        if tx is None:
            return None
        user_account_ids = AccountService.get_owned_account_ids(db, user_id)
        if tx.sender_account_id in user_account_ids or tx.receiver_account_id in user_account_ids:
            return tx
        return None
