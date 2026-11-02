"""Attack generators.

Two threat classes:
  SensorAttack  - compromised sensor: it HAS the key, so signatures stay VALID.
                  Crypto cannot catch these; plausibility + cross-validation + AI must.
  ChannelAttack - man-in-the-middle: no key. Crypto should catch these.

Methodology: thresholds were tuned ONLY with the DEV attacks. HELD_OUT attacks (new
families) and new random seeds are used for the final numbers - never tuned on.
"""
import json, os
import numpy as np
from crypto_layer import SecureElement, b64, canon, parts, unb64

DEV_ATTACKS = ("bias", "drift", "spike", "freeze")
HELD_OUT = ("stale_replay", "slow_bias", "evasion", "noise", "sawtooth", "zero_fault")
SENSOR_ATTACKS = DEV_ATTACKS + HELD_OUT
CHANNEL_ATTACKS = ("mitm_tamper", "mitm_replay", "mitm_forge", "mitm_drop")


class SensorAttack:
    """Magnitudes are in units of sigma = typical neighbour-residual noise of the victim
    (an adaptive attacker who knows the detector's scale)."""

    def __init__(self, kind, start, sigma, rng=None):
        self.kind, self.start, self.sigma = kind, start, sigma
        self.rng, self.frozen = rng or np.random.default_rng(0), None

    def is_attack(self, step):
        if self.kind == "none" or step < self.start:
            return False
        if self.kind == "spike":
            return (step - self.start) % 20 == 0
        return True

    def apply(self, step, true_value, history):
        if not self.is_attack(step):
            return true_value
        s, k = self.sigma, self.kind
        if k == "bias":
            return true_value + 6 * s
        if k == "slow_bias":
            return true_value + 0.9 * s
        if k == "evasion":          # stays under the CUSUM allowance
            return true_value + 0.45 * s
        if k == "drift":
            return true_value + 0.04 * s * (step - self.start)
        if k == "spike":
            return true_value + 12 * s
        if k == "noise":            # variance inflation, mean unchanged
            return true_value + self.rng.normal(0, 3 * s)
        if k == "sawtooth":         # ramp 0 -> 3 sigma, then reset, repeated
            return true_value + 3 * s * (((step - self.start) % 40) / 40)
        if k == "zero_fault":       # sensor reports 0 (dropout / spoofed fault)
            return 0.0
        if k == "freeze":
            if self.frozen is None:
                self.frozen = true_value
            return self.frozen
        if k == "stale_replay":     # re-sends genuine but old values, fresh seq + valid signature
            return history[max(0, step - 120)]
        raise ValueError(k)


class ChannelAttack:
    def __init__(self, kind, start, every, victim, mode):
        self.kind, self.start, self.every, self.victim = kind, start, every, victim
        alg, _ = parts(mode)
        self.alg = alg
        self.own_key = SecureElement(alg) if alg != "none" else None   # attacker's own key

    def active(self, sid, step):
        return (self.kind != "none" and sid == self.victim and step >= self.start
                and (step - self.start) % self.every == 0)

    def transform(self, raw, sid, step, archive):
        """Return (raw_to_deliver or None if dropped, is_attack)."""
        if not self.active(sid, step):
            return raw, False
        if self.kind == "mitm_drop":
            return None, True
        if self.kind == "mitm_replay":
            return archive[sid][step - 60], True
        msg = json.loads(raw)
        if self.kind == "mitm_tamper":      # modify in transit, no key
            if "v" in msg:
                msg["v"] = msg["v"] + 0.1
            else:                            # encrypted: flip one bit of the ciphertext
                ct = bytearray(unb64(msg["ct"]))
                ct[0] ^= 0x01
                msg["ct"] = b64(bytes(ct))
            return json.dumps(msg, separators=(",", ":")).encode(), True
        if self.kind == "mitm_forge":       # build own packet claiming to be the sensor
            forged = {"h": msg["h"]}
            if "ct" in msg:
                forged["n"] = msg["n"]
                forged["ct"] = b64(os.urandom(len(unb64(msg["ct"]))))
            else:
                forged["v"] = msg["v"] + 0.1
            if self.own_key is not None:
                forged["sig"] = b64(self.own_key.sign(canon(forged)))
            return json.dumps(forged, separators=(",", ":")).encode(), True
        raise ValueError(self.kind)
