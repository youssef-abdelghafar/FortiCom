# FortiCom

**Secure Earth Observation Data Integrity Framework**

*A simulation-based prototype for detecting false-data injection and protecting sensor-to-ground-station telemetry.*

FortiCom evaluates how cryptographic authentication, message protection, statistical checks, and anomaly detection can work together to protect an Earth Observation sensing chain.

> **Scope:** This is a software simulation prototype evaluated on a laptop. It is not a deployed satellite system, production security gateway, or replacement for hardware security modules and satellite communication standards.

## Overview

A valid digital signature proves that a message was produced by an entity holding the corresponding key. It does **not** prove that the sensor measurement is truthful. A compromised sensor may still use its legitimate key to sign false readings.

FortiCom evaluates two broad threat classes:

- **Compromised-sensor attacks:** manipulated measurements are sent while the sensor retains valid credentials.
- **Communication-channel attacks:** messages are tampered with, replayed, forged, or dropped in transit by an attacker without the sensor's private key.

The receiver combines cryptographic checks with freshness, replay, physical-range, rate, freeze, neighbour, CUSUM, and AI-based checks. Messages can be **ACCEPTED**, **QUARANTINED**, or **REJECTED**.

## Main features

### Cryptographic protection

Supported modes:

- `none`
- `hmac`
- `ed25519`
- `ed25519+gcm`
- `mldsa65`
- `mldsa65+gcm`

The implementation includes Ed25519 and ML-DSA-65 signatures, AES-256-GCM authenticated encryption, X25519 and ML-KEM-768 key-establishment components combined through HKDF-SHA256 for the hybrid session-key path, and a hash-chained audit log with a signed final seal.

These are software implementations in the simulation. The project does not use a physical HSM, TPM, QRNG, or satellite-grade key-management infrastructure.

### Detection and response

The receiver implements nine configurable checking layers:

1. Signature/authentication
2. Freshness
3. Replay detection
4. Physical-range validation
5. Rate-of-change validation
6. Freeze detection
7. Neighbour consistency
8. CUSUM
9. AI anomaly detection

An automatic isolation policy is simulated using alert counts. It does not isolate a real device or revoke credentials on a real network.

### Attack simulation

Ten sensor-side attack families:

`bias`, `drift`, `spike`, `freeze`, `stale_replay`, `slow_bias`, `evasion`, `noise`, `sawtooth`, `zero_fault`.

Four communication-channel attack types:

`mitm_tamper`, `mitm_replay`, `mitm_forge`, `mitm_drop`.

## Architecture and source files

| File | Responsibility |
|---|---|
| `data.py` | Generates synthetic correlated sensor data and supports wide-format numeric CSV input. |
| `attacks.py` | Implements compromised-sensor and communication-channel attack scenarios. |
| `crypto_layer.py` | Implements cryptographic modes, hybrid key-establishment components, packet protection, and the audit log. |
| `receiver.py` | Implements receiver-side validation layers and ACCEPT / QUARANTINE / REJECT decisions. |
| `ai.py` | Implements AI anomaly detection, including an autoencoder and Isolation Forest. |
| `evaluate.py` | Runs simulations and produces evaluation tables (T1–T8) and CSV outputs. |
| `selftest.py` | Runs lightweight correctness and regression checks. |
| `requirements.txt` | Lists Python dependencies. |
| `results_log.txt` | Recorded experiment output supplied with this repository. |

## Requirements

- Python 3.10 or newer
- Packages listed in `requirements.txt`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run the project

```bash
# Run self-tests
python selftest.py

# Quick evaluation
python evaluate.py --quick

# Full evaluation
python evaluate.py

# Run selected evaluation tables
python evaluate.py --only T3 T5

# Evaluate a wide-format CSV (one numeric column per sensor)
python evaluate.py --csv mydata.csv
```

The full evaluation writes CSV outputs under `results/`. Runtime depends on the machine and selected evaluation.

## Evaluation methodology

The recorded main test results use seeds **100–109** (ten seeds). Development used seeds **0–4**.

The project documentation records an important limitation in the held-out methodology:

- `stale_replay`, `slow_bias`, `evasion`, `noise`, `sawtooth`, and `zero_fault` are designated held-out attack families.
- However, the CUSUM parameters (`k = 0.75`, `h = 8`) and `z_thr = 4` came from an earlier project version and were tuned on seeds 0–4 after examining `slow_bias` and `evasion`.
- Therefore, `noise`, `sawtooth`, and `zero_fault` are the families that were truly unseen by every parameter according to the recorded methodology.

The evaluation reports mean values and 95% confidence intervals over seeds where applicable. Different experiments may use different numbers of runs; consult each table and the recorded log rather than assuming all results use the same sample size.

## Selected results

The following figures are from the recorded T3 evaluation (Ed25519 mode with the full receiver pipeline, including AI). Recall and precision are percentages. These are simulation results, not guarantees on operational satellite data.

| Attack family | Recall | Precision | Median detection latency (steps) |
|---|---:|---:|---:|
| `bias` | 99% | 100% | 0 |
| `drift` | 89% | 100% | 32 |
| `spike` | 100% | 92% | 0 |
| `freeze` | 99% | 100% | 3 |
| `stale_replay` | 95% | 99% | 0 |
| `slow_bias` | 84% | 100% | 11 |
| `evasion` | 6% | 59% | 151* |
| `noise` | 31% | 99% | 1 |
| `sawtooth` | 89% | 100% | 21 |
| `zero_fault` | 100% | 100% | 0 |
| `mitm_tamper` | 100% | 98% | 0 |
| `mitm_replay` | 100% | 98% | 0 |
| `mitm_forge` | 100% | 98% | 0 |

`*` Evasion latency was available in only 3 of the 10 runs; interpret it with that limitation.

### Interpreting the results

- Cryptographic checks performed well against the tested channel-tampering and forgery scenarios when the attacker did not possess the relevant secret keys.
- A compromised sensor with valid credentials is different: cryptographic authentication alone cannot establish that its measurement is truthful.
- Detection is weak against the tested `evasion` and `noise` scenarios. These limitations should be reported transparently.
- `mitm_drop` is evaluated separately because dropped messages do not reach the normal per-message detection pipeline. The recorded T7 experiment reports 60 dropped messages and 60 detected sequence gaps across ten runs.

See [`results_log.txt`](results_log.txt) for the recorded experiment output.

## Important limitations

- **Simulation only:** no real satellite, radio link, ground-station hardware, or operational network is connected.
- **No standards implementation:** the prototype does not implement CCSDS SDLS or IPsec.
- **No physical root of trust:** the software trust-anchor abstraction is not a hardware HSM or TPM.
- **Key lifecycle:** keys are generated at startup; persistent key storage, rotation, and a device-enrolment server are not implemented.
- **Synthetic data:** results use synthetic sensor data unless a CSV dataset is supplied. Performance on a real mission dataset has not been established.
- **Threat-model scope:** the simulation considers one compromised sensor at a time; neighbour checks assume correlated sensors.
- **Detection limits:** small biases can be difficult to distinguish from natural sensor noise. The recorded `evasion` results demonstrate this limitation.
- **AI scope:** anomaly detection is local to this simulation; it is not Federated Learning.
- **Response scope:** automatic isolation is simulated in-process; it does not perform real network isolation or credential revocation.
- **Audit scope:** the audit log is an in-memory hash chain with a signed final seal, not a persistent external append-only service.

## Reproducibility and responsible interpretation

Run the self-tests and evaluations in your own environment. When comparing results, record the Python version, dependency versions, command, seed configuration, and hardware.

Do not interpret simulation metrics as a certification, production security guarantee, or evidence of deployment readiness. Any use with real telemetry requires dataset validation, a documented threat model, independent security review, and testing on the target platform.

## Project context

Developed as a prototype for **TSYP Challenge – Track 2: False-Data Injection**, focused on the integrity and trustworthiness of Earth Observation sensor data.

---

**FortiCom — Trust the Data. Secure the Truth.**
