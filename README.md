# EO Trust - false-data injection defence prototype (Track 2)

Layered defence for an in-situ sensing -> ground station chain, evaluated by simulation on a
laptop (no hardware). Python 3.10+.

    pip install -r requirements.txt
    python selftest.py                    # 20 s: checks that everything works
    python evaluate.py --quick            # 3 seeds, a few minutes
    python evaluate.py                    # full evaluation, 10 held-out seeds, writes results/*.csv
    python evaluate.py --csv mydata.csv   # real dataset: wide CSV, one numeric column per sensor
    python evaluate.py --only T3 T5       # only some tables

## Files
| file | role |
|---|---|
| `crypto_layer.py` | 6 protection modes (none, hmac, ed25519, ed25519+gcm, mldsa65, mldsa65+gcm); software trust anchor; hybrid X25519 + ML-KEM-768 session keys; signed hash-chained audit log |
| `data.py` | data source (synthetic correlated sensors or CSV) - the only file to touch to change dataset |
| `attacks.py` | 10 compromised-sensor attacks (valid signature) and 4 man-in-the-middle attacks |
| `receiver.py` | ground station: 9 switchable layers -> ACCEPT / QUARANTINE / REJECT, optional automatic isolation |
| `ai.py` | AI layer: autoencoder (default) and Isolation Forest, trained on clean data only |
| `evaluate.py` | simulation, metrics, tables T1-T8 |
| `selftest.py` | quick correctness tests |

## Method
* The AI threshold and the receiver design fixes were made on DEV seeds 0-4 using only the DEV
  attacks (bias, drift, spike, freeze).
* Final numbers use TEST seeds 100-109, never used during development.
* HELD-OUT attack families: stale_replay, slow_bias, evasion, noise, sawtooth, zero_fault.
  Caveat: the CUSUM parameters (k = 0.75, h = 8) and z_thr = 4 come from an EARLIER version of the
  project, tuned on seeds 0-4 after looking at slow_bias and evasion. So the families that are truly
  unseen by every parameter are noise, sawtooth and zero_fault.
* Known interaction: removing the `neighbor` layer RAISES recall on `noise` (T4). Messages rejected
  by an instantaneous layer are removed from the AI window (to avoid false alarms after a spike),
  which weakens the AI view of variance attacks. Not fixed, to avoid tuning on a held-out attack.
* Calibration uses clean data only. Sensor-side packet generation is separated from receiver
  processing so that timing and memory are measured on the receiver alone.
* Tables show mean ± 95% confidence interval over seeds.

## Limits (state them in the report)
* In-process simulation: not an implementation of IPsec / CCSDS SDLS / HSM / TPM.
* Synthetic data unless `--csv` is used; the official reference dataset must be confirmed.
* One compromised sensor at a time; the neighbour check assumes several correlated sensors.
* Bias below ~0.75 sigma of the neighbour noise (`evasion`) is by design not separable from noise.
* Keys are generated at start-up; there is no persistent key store, rotation or enrolment server.
