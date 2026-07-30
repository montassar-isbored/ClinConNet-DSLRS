# DSLRS Hyperledger Fabric Integration

## Overview
This repository contains the smart contract chaincode and client application scripts for deploying and evaluating Deanonymizable Scoped Linkable Ring Signatures (DSLRS) within a Hyperledger Fabric distributed ledger environment. The system enables privacy-preserving, dynamic consent management with an integrated, threshold-based deanonymization mechanism.

## Repository Structure
The codebase is divided into the Node.js chaincode components and the Python-based cryptographic client applications.

*   `lib/consent_contract.js`: Smart contract implementing the mathematical verification, linkability constraints, and Share-to-Point Shamir's Secret Sharing threshold logic for DSLRS consent records.
*   `lib/identity_contract.js`: Smart contract managing the public key registry, which acts as the global anonymity set for ring construction.
*   `index.js` / `package.json`: Node.js module configuration and entry points for the Fabric chaincode package.
*   `dslrs_client.py`: Command-line interface application for fetching the registry state, sampling anonymity rings, generating cryptographic signatures locally over SECP256k1, and submitting lifecycle transactions (Publish, Revoke, Update, Deanonymize).
*   `benchmark_dslrs.py`: Automated performance testing suite. Executes the full consent lifecycle synchronously across multiple ring sizes and outputs processing metrics.
*   `dslrs_performance_benchmark.csv`: Data output file capturing local generation times and End-to-End (E2E) network consensus latencies.
*   `generate_registry_payload.py`: Utility script for generating bulk SECP256k1 key pairs and formatting the state initialization payload.
*   `populate_registry.sh`: Bash script to execute the initial chaincode invocation, registering the generated public keys to the ledger.
*   `signer_keys.txt`: Local keystore containing the hex-encoded private keys required for signature generation.

## Prerequisites
*   Hyperledger Fabric Test Network (v2.x) running locally.
*   Node.js (v18+) for chaincode execution.
*   Python 3.8+ with the `ecdsa` cryptography library installed.

## Usage

### 1. Chaincode Deployment and Initialization
Package and deploy the chaincode to the active Fabric channel. Execute the registry initialization script to populate the on-chain anonymity set:
```bash
./populate_registry.sh
```

### 2. Client Application (`dslrs_client.py`)
The client application requires a target action, a valid private key, and the target scope hashes. The `-n` parameter controls the sampled ring size.

**Publish Consent:**
```bash
python3 dslrs_client.py publish <priv_key_hex> <scope_hash> -n 16
```

**Update Consent:**
```bash
python3 dslrs_client.py update <priv_key_hex> <old_scope_hash> --scope_new <new_scope_hash> -n 16
```

**Revoke Consent:**
```bash
python3 dslrs_client.py revoke <priv_key_hex> <scope_hash> -n 16
```

**Simulate Deanonymization:**
```bash
python3 dslrs_client.py deanonymize DUMMY <target_scope_hash>
```

### 3. Automated Benchmarking (`benchmark_dslrs.py`)
The benchmarking suite executes 100 iterations of the full cryptographic lifecycle across ring sizes $n \in \{8, 16, 32\}$.
```bash
python3 benchmark_dslrs.py <priv_key_hex>
```
Metrics are recorded in `dslrs_performance_benchmark.csv`.

## Acknowledgements
This work is supported by the French National Research Agency under project TRACIA. 