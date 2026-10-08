from __future__ import annotations

from decimal import Decimal

from werkzeug.security import generate_password_hash

from app import app
from backend.database.database import Base, SessionLocal, engine
from backend.models.account import Account, AccountStatus, AccountType
from backend.models.user import User, UserRole


def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "module8-test-secret"
    return app.test_client()


def create_user(name: str, username: str, email: str, role: UserRole):
    with SessionLocal() as db:
        user = User(name=name, username=username, email=email, password_hash=generate_password_hash("StrongPass123!"), role=role, is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def create_account(user_id: str, number: str, balance: str = "10000.00"):
    with SessionLocal() as db:
        account = Account(user_id=user_id, account_number=number, account_type=AccountType.SAVINGS, balance=Decimal(balance), currency="INR", status=AccountStatus.ACTIVE)
        db.add(account)
        db.commit()
        db.refresh(account)
        return account


def login(test_client, email: str):
    return test_client.post("/api/auth/login", json={"email": email, "password": "StrongPass123!"})


def test_role_separation_for_pages_and_apis():
    reset_db()
    test_client = client()
    admin = create_user("Admin", "admin8", "admin8@example.com", UserRole.ADMIN)
    analyst = create_user("Analyst", "analyst8", "analyst8@example.com", UserRole.SECURITY_ANALYST)
    customer = create_user("Customer", "customer8", "customer8@example.com", UserRole.CUSTOMER)

    assert login(test_client, "admin8@example.com").status_code == 200
    assert test_client.get("/admin").status_code == 200
    assert test_client.get("/security").status_code == 200
    assert test_client.get("/api/admin/overview").status_code == 200
    assert test_client.get("/api/security/overview").status_code == 200

    assert login(test_client, "analyst8@example.com").status_code == 200
    assert test_client.get("/security").status_code == 200
    assert test_client.get("/admin").status_code == 403
    assert test_client.get("/api/security/overview").status_code == 200
    assert test_client.get("/api/admin/overview").status_code == 403

    assert login(test_client, "customer8@example.com").status_code == 200
    assert test_client.get("/admin").status_code == 403
    assert test_client.get("/security").status_code == 403
    assert test_client.get("/api/admin/users").status_code == 403
    assert test_client.get("/api/security/audit").status_code == 403


def test_analytics_reflect_real_transaction_and_exclude_sensitive_fields():
    reset_db()
    test_client = client()
    admin = create_user("Admin", "admin9", "admin9@example.com", UserRole.ADMIN)
    analyst = create_user("Analyst", "analyst9", "analyst9@example.com", UserRole.SECURITY_ANALYST)
    customer = create_user("Customer", "customer9", "customer9@example.com", UserRole.CUSTOMER)
    receiver = create_user("Receiver", "receiver9", "receiver9@example.com", UserRole.CUSTOMER)
    sender_account = create_account(customer.id, "ACC-M8-S", "5000.00")
    receiver_account = create_account(receiver.id, "ACC-M8-R", "1000.00")

    assert login(test_client, "customer9@example.com").status_code == 200
    transfer = test_client.post("/api/transactions", json={"sender_account_id": sender_account.id, "receiver_account_id": receiver_account.id, "amount": "500.00"})
    assert transfer.status_code == 200

    assert login(test_client, "admin9@example.com").status_code == 200
    overview = test_client.get("/api/admin/overview").get_json()
    assert overview["customers"] == 2
    assert overview["transactions"] == 1
    assert overview["completed_transactions"] == 1
    assert overview["blocks"] == 2
    assert overview["chain"]["valid"] is True

    users = test_client.get("/api/admin/users").get_json()["users"]
    assert users
    assert all("password_hash" not in user and "password" not in user for user in users)
    assert test_client.get("/api/admin/transactions").get_json()["transactions"][0]["algorithm"] == "ML-DSA-44"

    assert login(test_client, "analyst9@example.com").status_code == 200
    security = test_client.get("/api/security/overview").get_json()
    assert security["risk_distribution"]["LOW"] == 1
    assert security["algorithm_usage"]["ML-DSA-44"] == 1
    assert security["signatures"]["verified"] == 1
    assert security["blockchain"]["validation"]["valid"] is True
    assert test_client.get("/api/security/aqrs").status_code == 200
    assert test_client.get("/api/security/crypto").get_json()["signatures"]["total"] == 1
    assert test_client.get("/api/security/blockchain").status_code == 200
    assert test_client.get("/api/security/audit").status_code == 200


def test_all_monitoring_pages_render_for_authorized_roles():
    reset_db()
    test_client = client()
    create_user("Admin", "admin10", "admin10@example.com", UserRole.ADMIN)
    create_user("Analyst", "analyst10", "analyst10@example.com", UserRole.SECURITY_ANALYST)

    login(test_client, "admin10@example.com")
    for path in ("/admin", "/admin/users", "/admin/transactions", "/admin/audit"):
        assert test_client.get(path).status_code == 200

    login(test_client, "analyst10@example.com")
    for path in ("/security", "/security/aqrs", "/security/crypto", "/security/blockchain", "/security/audit"):
        assert test_client.get(path).status_code == 200
