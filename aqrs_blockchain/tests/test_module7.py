from __future__ import annotations

from decimal import Decimal

from werkzeug.security import generate_password_hash

from app import app
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.transaction import Transaction
from backend.models.user import User, UserRole


def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def make_client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-module7"
    return app.test_client()


def create_customer(email: str, username: str):
    with SessionLocal() as db:
        user = User(name=username.title(), username=username, email=email, password_hash=generate_password_hash("StrongPass123!"), role=UserRole.CUSTOMER, is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def create_account(user_id: str, number: str, balance: str):
    with SessionLocal() as db:
        account = Account(user_id=user_id, account_number=number, account_type=AccountType.SAVINGS, balance=Decimal(balance), currency="INR", status=AccountStatus.ACTIVE)
        db.add(account)
        db.commit()
        db.refresh(account)
        return account


def login(client, email: str):
    return client.post("/api/auth/login", json={"email": email, "password": "StrongPass123!"})


def test_customer_pages_load_and_protected_pages_redirect():
    reset_db()
    client = make_client()
    assert client.get("/").status_code == 200
    assert client.get("/login").status_code == 200
    assert client.get("/register").status_code == 200
    for path in ("/dashboard", "/transfer", "/transactions", "/transaction/example"):
        response = client.get(path)
        assert response.status_code == 302
        assert response.location.endswith("/login")


def test_registration_login_dashboard_and_account_data():
    reset_db()
    client = make_client()
    registration = client.post("/api/auth/register", json={"name": "UI Customer", "username": "ui_customer", "email": "ui@example.com", "password": "StrongPass123!", "role": "ADMIN"})
    assert registration.status_code == 400
    registration = client.post("/api/auth/register", json={"name": "UI Customer", "username": "ui_customer", "email": "ui@example.com", "password": "StrongPass123!"})
    assert registration.status_code == 201
    user = create_customer("second@example.com", "second")
    account = create_account(user.id, "ACC-UI-001", "5000.00")
    assert login(client, "second@example.com").status_code == 200
    assert client.get("/dashboard").status_code == 200
    accounts = client.get("/api/users/me/accounts").get_json()["accounts"]
    assert accounts[0]["account_type"] == "SAVINGS"
    assert accounts[0]["account_number"] == account.account_number


def test_transfer_history_security_block_and_logout():
    reset_db()
    client = make_client()
    sender_user = create_customer("sender-ui@example.com", "sender_ui")
    receiver_user = create_customer("receiver-ui@example.com", "receiver_ui")
    sender = create_account(sender_user.id, "ACC-UI-S", "5000.00")
    receiver = create_account(receiver_user.id, "ACC-UI-R", "1000.00")
    assert login(client, "sender-ui@example.com").status_code == 200
    transfer = client.post("/api/transactions", json={"sender_account_id": sender.id, "receiver_account_id": receiver.id, "amount": "500.00", "description": "UI transfer"})
    assert transfer.status_code == 200
    transaction = transfer.get_json()["transaction"]
    assert transaction["block_number"] >= 1
    transaction_id = transaction["transaction_id"]
    history = client.get("/transactions")
    assert history.status_code == 200
    assert client.get(f"/transaction/{transaction_id}").status_code == 200
    assert client.get(f"/api/transactions/{transaction_id}/security").get_json()["verification_status"] == "VERIFIED"
    assert client.get(f"/api/transactions/{transaction_id}/block").status_code == 200
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/dashboard").status_code == 302


def test_customer_cannot_access_another_customers_transaction_page_or_api():
    reset_db()
    client = make_client()
    owner = create_customer("owner-ui@example.com", "owner_ui")
    stranger = create_customer("stranger-ui@example.com", "stranger_ui")
    other = create_customer("other-ui@example.com", "other_ui")
    owner_account = create_account(owner.id, "ACC-UI-O", "5000.00")
    other_account = create_account(other.id, "ACC-UI-X", "1000.00")
    create_account(stranger.id, "ACC-UI-Z", "1000.00")
    login(client, "owner-ui@example.com")
    transfer = client.post("/api/transactions", json={"sender_account_id": owner_account.id, "receiver_account_id": other_account.id, "amount": "100.00"})
    transaction_id = transfer.get_json()["transaction"]["transaction_id"]
    client.post("/api/auth/logout")
    login(client, "stranger-ui@example.com")
    assert client.get(f"/transaction/{transaction_id}").status_code == 404
    assert client.get(f"/api/transactions/{transaction_id}/block").status_code in {403, 404}