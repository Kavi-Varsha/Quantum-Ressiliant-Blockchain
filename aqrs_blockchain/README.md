# PQBank

Adaptive Post-Quantum Secure Banking Using Blockchain and AQRS.

## Problem Statement

This project addresses the research question: how can adaptive post-quantum cryptographic security be applied to blockchain-based financial transactions while balancing security and computational/storage overhead?

The current repository is a working prototype focused on research validation and benchmarking. It compares classical ECDSA with post-quantum Dilithium signatures, adapts the signature strength to transaction risk via AQRS, and evaluates the resulting blockchain performance.

## Research Contribution

The central research contribution is the Adaptive Quantum-Readiness Scoring (AQRS) layer. It maps transaction risk to a suitable Post-Quantum security level:

- LOW -> Dilithium Level 2
- MEDIUM -> Dilithium Level 3
- HIGH -> Dilithium Level 5

The project measures the trade-off between stronger cryptographic protection and increased signing time, verification time, signature size, and blockchain footprint.

## CURRENTLY IMPLEMENTED

- Transaction generation with risk classification
- ECDSA signing and verification
- Dilithium Level 2, Level 3, and Level 5 signing and verification
- AQRS-based security-level selection
- Simple blockchain chaining with block creation and chain-size metrics
- Offline simulation for ECDSA, DIL2, DIL3, DIL5, and AQRS modes
- Plot generation for timing, size, throughput, and AQRS comparison
- Flask-based prototype API for transaction and signature experimentation

## PLANNED

- Banking user and account model
- Authentication and authorization
- Persistent database layer
- REST API design for real banking workflows
- Modular service architecture
- Frontend pages for customer and admin/researcher flows
- Long-term production-grade blockchain integration
- Audit, tamper detection, and analytics services

## Existing Architecture

The current prototype is a single-layer research implementation with responsibilities concentrated in a few modules:

- `main.py` orchestrates the benchmark pipeline
- `transaction_generator.py` creates synthetic transactions and risk labels
- `signature_engine.py` wraps ECDSA and Dilithium operations
- `blockchain.py` maintains the chain and pending transactions
- `simulation.py` runs one benchmark mode and aggregates metrics
- `aqrs_calculator.py` calculates AQRS scores
- `visualizer.py` generates plots and summary output
- `app.py` exposes a Flask API that mixes transaction processing, signing, verification, and blockchain logic in one place

## Target Architecture

The final architecture will separate the system into the following layers:

1. Presentation Layer
2. API Layer
3. Service Layer
4. Domain/Core Layer
5. Persistence Layer
6. Research Layer

The project is intentionally planned to evolve into:

- a banking application for real transactions and user flows
- a research lab for benchmarking and simulation
- a shared core for AQRS, cryptography, and blockchain logic

## Technology Stack

- Python 3
- Flask
- cryptography
- dilithium-py
- matplotlib
- pandas
- JSON-based research artifacts

## Module 2: Authentication & Authorization

This repository now includes the Module 2 foundation for secure banking access control. It keeps the original research engine unchanged while adding a database-backed authentication layer on top of the existing `User`, `Account`, and `AuditLog` models created in Module 1.

### Authentication architecture

```text
Client
↓
Auth API
↓
Authentication Service
↓
User Repository
↓
Database
```

```text
Request
↓
Authentication
↓
User
↓
Role Authorization
↓
Protected Resource
```

### Authentication mechanism

- Session-based authentication is used with Flask server-side sessions.
- Passwords are hashed using Werkzeug's `generate_password_hash` and validated with `check_password_hash`.
- Secrets are loaded from environment variables via `.env.example`.
- The identity used for authorization is always loaded from the database user record, never from client-provided role input.
- JWT is not required for this module because the project already uses Flask sessions and the auth scope is intentionally limited to the prototype stage.

### Roles

- `CUSTOMER`: default role for public registration.
- `ADMIN`: protected administrative access.
- `SECURITY_ANALYST`: protected research/security access.

### Authorization rules

- Public registration can only create `CUSTOMER` users.
- `ADMIN` is required for `/api/admin/test`.
- `SECURITY_ANALYST` is required for `/api/security/test`.
- Customers can only access their own accounts via `/api/accounts/<account_id>`.
- Admins may access protected account views for oversight, but customer ownership checks remain enforced for normal users.

### API endpoints

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/admin/test`
- `GET /api/security/test`
- `GET /api/users/me/accounts`
- `GET /api/accounts/<account_id>`

### Environment variables

Create or update a local `.env` file based on `.env.example`:

```bash
SECRET_KEY=your-local-secret
JWT_SECRET_KEY=your-local-jwt-secret
DATABASE_URL=sqlite:///./pqbank.db
DATABASE_ECHO=false
```

### Development user creation

For local testing, create a standard user through the registration endpoint. Example payload:

```json
{
  "name": "Test Customer",
  "email": "customer@example.com",
  "username": "customer",
  "password": "StrongPass123!"
}
```

Then log in via:

```json
{
  "email": "customer@example.com",
  "password": "StrongPass123!"
}
```

### Risk classification and AQRS decision flow

The banking flow now classifies each transfer before the post-quantum policy is selected:

```text
Transaction
↓
Risk Classification
↓
LOW / MEDIUM / HIGH
↓
AQRS Decision
↓
DIL2 / DIL3 / DIL5
↓
Persist Decision
↓
Transaction Complete
```

Risk rules:
- LOW: amount < ₹1,000
- MEDIUM: ₹1,000 ≤ amount < ₹100,000
- HIGH: amount ≥ ₹100,000

AQRS security mapping:
- LOW → DIL2 / ML-DSA-44
- MEDIUM → DIL3 / ML-DSA-65
- HIGH → DIL5 / ML-DSA-87

This module does not perform live cryptographic signing or verification. It decides which post-quantum level the transaction should use next, based on the project’s benchmark-driven AQRS policy. The benchmark AQRS score remains a comparative research score; it is not a per-transaction mathematical guarantee of quantum security.

The AQRS decision is persisted in the database alongside the transaction and audit log so the decision can be reviewed without mixing it with signing or blockchain behavior.

### Running the authentication tests

```bash
python -m pytest tests/test_auth.py -q
python -m pytest -q
```

### Security limitations

This module is intentionally limited to the prototype stage. It does not claim production banking-grade security; it provides a safe and auditable auth foundation with hashed passwords, DB-backed roles, and ownership checks for the next development phases.

## Module 6: Persistent Tamper-Evident Ledger

Completed banking transactions are added to a persistent SQLAlchemy-backed ledger only after account validation, balance updates, AQRS decision persistence, ML-DSA signing, and signature verification succeed. The database remains the system of record; the ledger adds hash linkage and integrity validation through the `Block` model and `Transaction.block_id` relationship.

The persistent ledger provides:

- One deterministic genesis block at index `0` with a zero-hash previous reference.
- SHA-256 block hashes over canonical block metadata and normalized transaction/signature references.
- Previous-block hash linkage and transaction-to-block association.
- Block and full-chain validation, including detection of block, transaction, signature-reference, and linkage changes.
- `BLOCK_CREATED` audit events for ledger inclusion.

Explorer endpoints are restricted to `ADMIN` and `SECURITY_ANALYST` roles:

- `GET /api/blockchain`
- `GET /api/blockchain/validate`
- `GET /api/blockchain/blocks/<block_number>`
- `GET /api/transactions/<transaction_id>/block` for an authorized transaction owner or privileged role

This is an academic persistent tamper-evident ledger for the banking prototype. It is not a decentralized, permissionless, mining-based, cryptocurrency, consensus, or Byzantine-fault-tolerant blockchain. The original in-memory research implementation in `blockchain.py` remains independently executable and unchanged.

## How to Run the Current Research Simulation

From the project root:

```bash
pip install -r requirements.txt
python main.py
```

This generates:

- `results.json`
- `plots/*.png`
- console metrics and AQRS summary

To run the prototype Flask API:

```bash
python app.py
```

Then open the local endpoint at `http://127.0.0.1:5000`.

## Future Development Roadmap

### Module 0
- Audit the research prototype
- Define target architecture
- Establish repository structure
- Preserve research engine
- Record baseline metrics

### Module 1
- Database design and entity modeling
- Repository and persistence layer design
- Data model for users, accounts, transactions, signatures, AQRS decisions, blocks, and audit logs

### Module 2
- Banking core service layer
- Risk engine and AQRS service
- Crypto service abstraction
- Blockchain service abstraction

### Module 3
- REST API layer and route groups
- Transaction and account workflows
- Research endpoints

### Module 4
- Frontend pages and dashboard flows
- Research lab UI and experiment monitoring

## Important Note

This repository must preserve the research engine as a separate concern from the future banking application. The research layer remains essential to the project’s academic and engineering contribution.
