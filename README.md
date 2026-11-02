 <div align="center">

# FortiCom

### Secure Earth Observation Data Integrity Framework

**Trust the Data. Secure the Truth.**

*A simulation-based prototype for detecting false-data injection and protecting sensor-to-ground-station telemetry.*

</div>

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [The Problem](#2-the-problem)
3. [Threat Model](#3-threat-model)
4. [Proposed Approach](#4-proposed-approach)
5. [System Architecture](#5-system-architecture)
6. [Security and Detection Components](#6-security-and-detection-components)
7. [Attack Scenarios](#7-attack-scenarios)
8. [AI-Based Anomaly Detection](#8-ai-based-anomaly-detection)
9. [Experimental Methodology](#9-experimental-methodology)
10. [Selected Experimental Results](#10-selected-experimental-results)
11. [Installation and Usage](#11-installation-and-usage)
12. [Repository Structure](#12-repository-structure)
13. [Current Limitations](#13-current-limitations)
14. [Future Roadmap](#14-future-roadmap)
15. [Reproducibility and Responsible Use](#15-reproducibility-and-responsible-use)
16. [Project Context](#16-project-context)

---

## 1. Project Overview

FortiCom is a Python-based research prototype exploring how to improve the integrity and trustworthiness of Earth Observation (EO) sensor data as it travels from sensing devices to a ground-station receiver.

The prototype combines cryptographic protection, message-freshness checks, statistical validation, cross-sensor consistency checks, change detection, and AI-based anomaly detection. It evaluates these mechanisms in a controlled simulation containing both compromised-sensor and communication-channel attack scenarios.

**The central design principle is that message authenticity and measurement truthfulness are different security properties.**

A valid digital signature can establish that a message was signed by a trusted device and was not modified after signing. However, it cannot prove that the device itself is measuring or reporting honestly.

FortiCom explores a layered receiver-side approach in which cryptography is combined with checks on the behaviour and consistency of sensor measurements.

> **Project scope:** FortiCom is currently a software simulation and research prototype. It is not a deployed satellite security system, a production ground-station gateway, or a certified implementation of a space-security standard.

## 2. The Problem

Earth Observation systems depend on data collected by sensors and delivered through communication links to ground infrastructure. The integrity of this data matters because decisions and downstream analysis may rely on measurements being both authentic and plausible.

Two different situations must be distinguished:

### 2.1 Communication compromise

An attacker modifies, forges, or replays a message while it is travelling through the communication channel.

Cryptographic authentication and integrity mechanisms are designed to help detect or prevent these actions.

### 2.2 Sensor compromise

An attacker controls a legitimate sensor or its measurement process. The sensor may continue using its valid credentials while reporting manipulated measurements.

This is a different problem: the message may be cryptographically authentic while its content is false.

FortiCom focuses on exploring how a receiver can identify suspicious measurements even when their cryptographic authentication is valid.

## 3. Threat Model

The current simulation models two main attacker classes.

### 3.1 Compromised sensor

The attacker manipulates the readings of a sensor that still possesses its legitimate signing credentials.

Consequently, generated messages can have valid signatures even when their measurements are false.

This scenario evaluates statistical, temporal, cross-sensor, and AI-based detection.

### 3.2 Communication-channel attacker

The attacker acts on messages in transit but does not possess the sensor's private signing key.

Simulated actions include tampering, replay, forgery, and message dropping.

This scenario evaluates cryptographic integrity, freshness, and sequence-based gap detection.

### 3.3 Threat-model scope

The current evaluation focuses on one compromised sensor at a time and a simulated receiver.

It does not claim to cover every possible adversary, multi-sensor collusion, compromised ground-station infrastructure, supply-chain attacks, or operational satellite-network conditions.

## 4. Proposed Approach

FortiCom uses a layered processing pipeline:

1. Generate or load time-aligned sensor measurements.
2. Apply a selected sensor-side or communication-channel attack.
3. Build and protect telemetry packets using a selected cryptographic mode.
4. Deliver packets to the simulated ground-station receiver.
5. Validate message authenticity, freshness, sequence, and measurement behaviour.
6. Produce a receiver decision and record relevant events in the audit log.
7. Evaluate detection quality, false alarms, latency, communication overhead, and processing cost.

The receiver can classify messages into three outcomes:

- **ACCEPT:** no enabled check has raised an alert.
- **QUARANTINE:** the message or sensor is flagged for further handling.
- **REJECT:** the message fails a relevant validation check.

The prototype also includes an optional simulated response policy that can isolate a sensor after repeated alerts.

This is an in-process simulation action, not real network isolation.

## 5. System Architecture

The logical processing flow is:

```text
              SENSOR / DATA SOURCE
          Synthetic data or numeric CSV
                      |
                      v
              ATTACK SIMULATION
        +-----------------------------+
        | Compromised-sensor attacks  |
        | Communication-channel MITM |
        +-----------------------------+
                      |
                      v
              PACKET PROTECTION
        +-----------------------------+
        | HMAC / Ed25519 / ML-DSA-65  |
        | Optional AES-256-GCM        |
        | X25519 / Hybrid key setup   |
        +-----------------------------+
                      |
                      v
           SIMULATED GROUND STATION
        +-----------------------------+
        | Signature / authentication  |
        | Freshness and replay checks |
        | Range / rate / freeze       |
        | Neighbour consistency       |
        | CUSUM and AI detection      |
        +-----------------------------+
                      |
                      v
          ACCEPT / QUARANTINE / REJECT
                      |
                      v
               AUDIT AND EVALUATION
        Hash-chain log, signed seal,
        metrics, tables, and CSV output
```

This diagram describes the logical flow implemented by the software prototype. It does not represent a deployed satellite, radio link, or physical ground-station architecture.

## 6. Security and Detection Components

### 6.1 Cryptographic protection modes

The prototype supports six packet-protection modes:

| Mode | Authentication / signature | Payload encryption |
|---|---|---|
| `none` | None (baseline) | No |
| `hmac` | HMAC-SHA256 | No |
| `ed25519` | Ed25519 | No |
| `ed25519+gcm` | Ed25519 | AES-256-GCM |
| `mldsa65` | ML-DSA-65 | No |
| `mldsa65+gcm` | ML-DSA-65 | AES-256-GCM |

The implementation uses canonical JSON serialization when constructing data to be authenticated or signed.

For encrypted modes, AES-256-GCM provides authenticated encryption.

The key-establishment paths use:

- **X25519:** classical key agreement.
- **ML-KEM-768:** post-quantum key-encapsulation component in the hybrid path.
- **HKDF-SHA256:** derives session-key material from shared secrets.

The hybrid path combines X25519 and ML-KEM-768 shared-secret material before key derivation. The implemented handshake flow also uses an Ed25519 signature to authenticate its key-establishment message.

These components are evaluated as software libraries in a simulation. Their inclusion does not constitute a complete post-quantum secure protocol, a formal security proof, or a production-ready key-management design.

### 6.2 Receiver-side detection layers

The receiver implements nine configurable layers:

| Layer | Purpose |
|---|---|
| Signature | Verifies message origin and integrity when authentication is enabled. |
| Freshness | Checks whether the packet timestamp is within the configured freshness window. |
| Replay | Checks sequence progression and identifies sequence gaps. |
| Range | Checks measurements against bounds learned from clean calibration data. |
| Rate | Detects implausible changes between consecutive readings. |
| Freeze | Detects values that remain almost unchanged for an unusually long period. |
| Neighbour | Compares a sensor's residual with the median behaviour of other sensors. |
| CUSUM | Detects persistent small deviations and gradual changes. |
| AI | Uses window-based features for anomaly detection. |

The statistical and AI layers are calibrated using clean data in the current experimental setup.

The neighbour layer assumes that multiple sensors have sufficiently correlated behaviour for cross-checking to be meaningful.

### 6.3 Audit logging

The software includes a hash-chained audit log and a signed final seal.

The recorded experiment checks whether the chain and seal remain valid after tampering attempts.

The current log is held in memory during execution. It is not a persistent, externally anchored, append-only logging service.

## 7. Attack Scenarios

### 7.1 Compromised-sensor attacks

The prototype includes ten sensor-side attack families:

| Attack | Simulated behaviour |
|---|---|
| `bias` | Adds a persistent offset to the true reading. |
| `drift` | Gradually increases the measurement error over time. |
| `spike` | Injects periodic large deviations. |
| `freeze` | Repeats a previously observed value. |
| `stale_replay` | Reuses an older measurement. |
| `slow_bias` | Adds a persistent but relatively small offset. |
| `evasion` | Uses a small offset intended to remain difficult to distinguish from normal variation. |
| `noise` | Increases measurement variance without intentionally shifting the mean. |
| `sawtooth` | Applies a ramping deviation followed by a reset. |
| `zero_fault` | Forces the sensor output to zero. |

### 7.2 Communication-channel attacks

Four channel attack types are implemented:

- `mitm_tamper` — modifies a message in transit.
- `mitm_replay` — replays a previously observed message.
- `mitm_forge` — attempts to inject a forged message without the legitimate signing key.
- `mitm_drop` — drops messages before they reach the receiver.

The `mitm_drop` scenario is evaluated separately because a dropped packet cannot be processed by the normal per-message detection pipeline. Sequence-gap detection is used to identify missing messages.

## 8. AI-Based Anomaly Detection

The AI component operates on window-based features derived from receiver-side sensor behaviour.

The feature set includes the current deviation, recent and overall averages, recent variability, trend, repeated-value behaviour, and jump information.

Two model options are implemented:

### FastAutoencoder

A small neural autoencoder trained on clean features. Reconstruction error is used as the anomaly score.

### FastIForest

An Isolation Forest implementation based on a fitted scikit-learn model, with a custom single-sample tree traversal for streaming-style scoring.

The self-test checks the custom Isolation Forest scoring against scikit-learn scores on a test sample.

**AI scope:** these models run locally inside the simulation. FortiCom does not currently implement Federated Learning, distributed model aggregation, or a production model-monitoring pipeline.

## 9. Experimental Methodology

The recorded evaluation uses multiple experiments (T1–T8) to examine:

- Cryptographic primitive performance.
- Protection-mode overhead.
- Communication-channel attacks.
- The full detection pipeline.
- Individual detection-layer contributions.
- AI configurations.
- Automated response.
- Message-drop detection.

### 9.1 Development and test seeds

- Development used seeds `0–4`.
- The recorded main test results use seeds `100–109` (ten seeds).
- The results log reports means and 95% confidence intervals where applicable.
- Timing and memory measurements are taken on the receiver side; packet generation is separated from receiver processing in the evaluation design.

### 9.2 Held-out methodology caveat

The attack families `stale_replay`, `slow_bias`, `evasion`, `noise`, `sawtooth`, and `zero_fault` are designated as held-out families in the experiment.

However, the recorded methodology explicitly notes that the CUSUM parameters (`k = 0.75`, `h = 8`) and `z_thr = 4` originated in an earlier project version and were tuned on seeds `0–4` after examining `slow_bias` and `evasion`.

Therefore, **`noise`, `sawtooth`, and `zero_fault` are the families documented as truly unseen by every parameter**.

The other designated held-out families should not be presented as completely untouched by all prior parameter tuning.

### 9.3 Interpretation caveats

- Results are specific to the implemented simulation, datasets, seeds, and configuration.
- Different experiment tables may use different run counts and protocols.
- The `evasion` latency statistic is available for only 3 of 10 runs in T3.
- Message drops are evaluated separately in T7 and are not included as ordinary delivered-message detections in T3.
- The results log contains separate experiment protocols; values from different tables should not be combined as if they were one identical run.

## 10. Selected Experimental Results

The following figures are taken from the recorded **T3 full-pipeline experiment** using Ed25519 and all receiver layers, including AI.

Recall and precision are percentages. Latency is expressed in simulation steps.

| Attack | Evaluation group | Recall | Precision | Median latency |
|---|---|---:|---:|---:|
| `bias` | Development family | 99% | 100% | 0 |
| `drift` | Development family | 89% | 100% | 32 |
| `spike` | Development family | 100% | 92% | 0 |
| `freeze` | Development family | 99% | 100% | 3 |
| `stale_replay` | Designated held-out | 95% | 99% | 0 |
| `slow_bias` | Designated held-out | 84% | 100% | 11 |
| `evasion` | Designated held-out | 6% | 59% | 151* |
| `noise` | Designated held-out | 31% | 99% | 1 |
| `sawtooth` | Designated held-out | 89% | 100% | 21 |
| `zero_fault` | Designated held-out | 100% | 100% | 0 |
| `mitm_tamper` | Channel | 100% | 98% | 0 |
| `mitm_replay` | Channel | 100% | 98% | 0 |
| `mitm_forge` | Channel | 100% | 98% | 0 |

`*` The `evasion` latency value was available in only 3 of 10 runs. It must be interpreted with that limitation.

### 10.1 Additional recorded findings

- In T1b, the recorded receiver processing cost ranged from approximately **50 µs/message** for `none` to **393 µs/message** for `mldsa65+gcm` under the stated benchmark conditions.
- In T1b, the recorded message size ranged from **63 bytes** (`none`) to **4,552 bytes** (`mldsa65+gcm`), including the measured packet overhead.
- In T7, the separate message-drop experiment reports **60 dropped messages and 60 detected sequence gaps across ten runs**.
- The audit experiment reports that the original chain and seal validate, while rewriting an entry and recomputing the chain does not preserve the validity of the signed final seal.

### 10.2 What the results mean

The recorded results show that the implemented cryptographic checks detect the tested channel tampering and forgery scenarios when the attacker does not possess the relevant secret key.

They also show why sensor-side anomaly detection is necessary: a compromised sensor can produce authenticated but manipulated measurements.

Detection performance varies substantially by attack family. In particular, the recorded T3 recall is low for `evasion` and `noise`, and these weaknesses should remain visible in any technical presentation of the project.

See [`results_log.txt`](results_log.txt) for the full recorded experiment output, including T1–T8 and the associated measurements.

## 11. Installation and Usage

### 11.1 Requirements

- Python 3.10 or newer.
- Dependencies listed in `requirements.txt`.

### 11.2 Installation

Clone the repository:

```bash
git clone https://github.com/youssef-abdelghafar/FortiCom.git
cd FortiCom
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

### 11.3 Run the self-tests

```bash
python selftest.py
```

The self-test checks selected correctness properties, including packet round trips and tamper detection, the custom Isolation Forest scorer against scikit-learn, low false alarms on selected clean seeds, and detection of a bias attack with a valid signature.

Passing these tests is a useful development check; it is not a formal security audit or proof of production readiness.

### 11.4 Run evaluations

Quick evaluation:

```bash
python evaluate.py --quick
```

Full evaluation:

```bash
python evaluate.py
```

Run selected tables:

```bash
python evaluate.py --only T3 T5
```

Evaluate a wide-format CSV dataset:

```bash
python evaluate.py --csv mydata.csv
```

For CSV input, each numeric column represents one time-aligned sensor. The current loader uses the first five numeric columns for the five simulated sensors. Ensure the dataset is appropriate for this assumption before interpreting the results.

The full evaluation writes generated CSV outputs under `results/`. Runtime depends on the selected experiment and the machine.

## 12. Repository Structure

| File | Responsibility |
|---|---|
| `ai.py` | Autoencoder and fast Isolation Forest anomaly-scoring implementations. |
| `attacks.py` | Sensor-side and communication-channel attack generators. |
| `crypto_layer.py` | Packet protection, signatures, encryption, key-establishment flow, and audit log. |
| `data.py` | Synthetic correlated sensor data and wide-format CSV loading. |
| `evaluate.py` | Simulation orchestration, benchmark tables T1–T8, metrics, and CSV output. |
| `receiver.py` | Receiver validation layers, decisions, and simulated response policy. |
| `selftest.py` | Lightweight correctness and regression checks. |
| `requirements.txt` | Python package dependencies. |
| `results_log.txt` | Recorded experiment output used for the selected results in this README. |

## 13. Current Limitations

FortiCom is an experimental prototype. Its current limitations include:

1. **Simulation only:** no real satellite, radio link, operational ground station, or live telemetry network is connected.
2. **No standards implementation:** the prototype does not implement CCSDS SDLS, IPsec, or a complete space communication security stack.
3. **No hardware root of trust:** the `SecureElement` class is a software abstraction; it is not a physical HSM, TPM, or secure element.
4. **Key lifecycle:** keys are generated at startup. Persistent key storage, production provisioning, key rotation, and a device-enrolment service are not implemented.
5. **No demonstrated forward secrecy:** the current prototype should not be presented as a complete, formally analysed key-exchange protocol.
6. **Data realism:** results use synthetic data unless a CSV dataset is supplied. Performance on a validated mission dataset has not been established.
7. **Threat-model scope:** the current experiments focus on one compromised sensor at a time and do not establish resilience to colluding compromised sensors.
8. **Detection limitations:** the `evasion` and `noise` results show that subtle or variance-based attacks remain difficult for the current detector.
9. **AI scope:** the models are local to the simulation; Federated Learning and distributed model aggregation are not implemented.
10. **Response scope:** automatic isolation is simulated in-process; no real network device is disconnected and no production credential revocation occurs.
11. **Audit persistence:** the hash-chain log is held in memory and is not anchored to an external persistent append-only service.
12. **Operational validation:** no independent penetration test, formal verification, safety certification, or operational deployment assessment is claimed.

## 14. Future Roadmap

The following items are **proposed development directions**, not features currently implemented or validated. Their priority and scope may change according to evaluation findings, available resources, and project requirements.

### Phase 1 — Prototype Hardening

- Improve detection performance against difficult attack families, especially `evasion` and `noise`.
- Expand regression tests and edge-case coverage.
- Improve experiment reproducibility and document configuration, versions, and hardware.
- Evaluate suitable public datasets and define a repeatable data-validation process.

### Phase 2 — Advanced Security and Key Management

- Design a more complete key lifecycle, including secure provisioning, rotation, and revocation.
- Explore integration with hardware-backed security such as HSMs or TPMs.
- Study authenticated communication designs and relevant space-security standards.
- Add persistent audit storage with external integrity anchoring.

### Phase 3 — Distributed Intelligence

- Investigate Federated Learning across multiple simulated ground stations.
- Evaluate distributed anomaly detection under heterogeneous sensor conditions.
- Study resilience against data poisoning, model manipulation, and adversarial machine-learning attacks.

### Phase 4 — Realistic Earth Observation Integration

- Evaluate validated Earth Observation datasets and more realistic telemetry conditions.
- Investigate interoperability with relevant CCSDS standards.
- Develop a hardware-in-the-loop testbed before considering any operational integration.
- Conduct independent security and performance assessments.

## 15. Reproducibility and Responsible Use

For reproducible comparisons, record at least:

- Python version and dependency versions.
- Operating system and hardware configuration.
- Exact command and evaluation tables selected.
- Random seeds and dataset version.
- Any changes to thresholds, model settings, or receiver configuration.

Do not interpret the simulation metrics as a certification, production security guarantee, or evidence of deployment readiness.

Any use with real telemetry would require dataset validation, a documented operational threat model, independent security review, and testing on the target platform.

## 16. Project Context

FortiCom is developed as a prototype for the **TSYP Challenge — Track 2: False-Data Injection**, addressing the integrity and trustworthiness of Earth Observation sensor data.

The project is intended as an experimental foundation for studying layered protection and detection, not as a claim that all operational space-system security requirements have been solved.

---

<div align="center">

**FortiCom — Trust the Data. Secure the Truth.**

</div>