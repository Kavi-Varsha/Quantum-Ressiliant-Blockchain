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
