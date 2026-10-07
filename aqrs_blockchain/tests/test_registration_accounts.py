from __future__ import annotations

import app as app_module

from app import app
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.user import User


def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def make_client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-registration-accounts"
    return app.test_client()


def register(client, email="new-account@example.com", username="new_account"):
    return client.post(
        "/api/auth/register",
        json={
            "name": "New Customer",
            "email": email,
            "username": username,
            "password": "StrongPass123!",
        },
    )


def test_new_customer_gets_one_controlled_savings_account():
    reset_db()
    client = make_client()

    response = register(client)
    assert response.status_code == 201

    with SessionLocal() as db:
        user = db.query(User).filter_by(email="new-account@example.com").one()
        accounts = db.query(Account).filter_by(user_id=user.id).all()

    assert len(accounts) == 1
    assert accounts[0].account_type == AccountType.SAVINGS
    assert accounts[0].status == AccountStatus.ACTIVE
    assert accounts[0].balance == 10000
    assert accounts[0].currency == "INR"
    assert accounts[0].account_number.startswith("INR-")


def test_duplicate_registration_does_not_create_another_account():
    reset_db()
    client = make_client()

    assert register(client).status_code == 201
    assert register(client).status_code == 409

    with SessionLocal() as db:
        user = db.query(User).filter_by(email="new-account@example.com").one()
        assert db.query(Account).filter_by(user_id=user.id).count() == 1
        assert db.query(User).count() == 1


def test_registration_rolls_back_user_when_account_creation_fails(monkeypatch):
    reset_db()
    client = make_client()

    def fail_account_creation(*args, **kwargs):
        raise RuntimeError("simulated account creation failure")

    monkeypatch.setattr(app_module, "Account", fail_account_creation)
    response = register(client, email="rollback@example.com", username="rollback_user")

    assert response.status_code == 500
    with SessionLocal() as db:
        assert db.query(User).filter_by(email="rollback@example.com").count() == 0
        assert db.query(Account).count() == 0
