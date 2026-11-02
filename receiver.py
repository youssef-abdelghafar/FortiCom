"""Ground station: layered verification. Every layer is independent and can be switched
on/off in cfg (-> ablation study). Decision: ACCEPT / QUARANTINE / REJECT.

Layers (in order):
  signature  verify origin + integrity (crypto_layer)
  fresh      timestamp inside a window                (replay of old packets)
  replay     strictly increasing sequence number      (replay) + gap counting (dropped messages)
  range      physical bounds learned from clean data
  rate       maximum plausible change between readings
  freeze     value repeated longer than ever seen when clean
  neighbor   robust z-score against the median of the OTHER sensors
  cusum      slow drift / small persistent bias of that z-score
  ai         autoencoder (or Isolation Forest) on window features of the z-score (see ai.py)
Optional response (cfg["response"]): a sensor with too many alerts is isolated.
"""
import statistics
from collections import Counter, deque
from time import perf_counter
import numpy as np
from ai import FastAutoencoder, FastIForest
from crypto_layer import AuditLog, VerifyError, open_packet

LAYERS = ("signature", "fresh", "replay", "range", "rate", "freeze", "neighbor", "cusum", "ai")
STAT_LAYERS = ("range", "rate", "freeze", "neighbor", "cusum")
ZCAP = 8.0


def mad_sigma(x):
    x = np.asarray(x, float)
    return max(1.4826 * np.median(np.abs(x - np.median(x))), 1e-9)


class Windows:
    """Per-sensor recent history used to build the AI features."""

    def __init__(self):
        self.z, self.flat, self.prev = deque(maxlen=30), deque(maxlen=10), None

    def push(self, z, v, eps):
        if z is not None:
            self.z.append(max(-ZCAP, min(ZCAP, z)))
        self.flat.append(1.0 if self.prev is not None and abs(v - self.prev) <= eps else 0.0)
        self.prev = v

    def drop_z(self):
        """Remove the latest z (a message already judged bad must not poison later features)."""
        if self.z:
            self.z.pop()

    def features(self, jump):
        if len(self.z) < 10:
            return None
        z = np.fromiter(self.z, float)
        n, last = len(z), z[-10:]
        x = np.arange(n) - (n - 1) / 2
        slope = float((x * (z - z.mean())).sum() / (x * x).sum())
        return [z[-1], last.mean(), z.mean(), last.std(), slope,
                sum(self.flat) / len(self.flat), min(jump, 20.0)]


class Receiver:
    def __init__(self, mode, registry, cfg=None, z_thr=4.0, k=0.75, h=8.0,
                 fresh_window=5.0, max_age=3, ai_kind="autoencoder", ai_margin=0.08, ai_factor=4.0,
                 iso_after=15, seed=0):
        self.mode, self.registry = mode, registry
        self.cfg = {l: True for l in LAYERS}
        self.cfg["response"] = False
        if cfg:
            self.cfg.update(cfg)
        self.z_thr, self.k, self.h, self.max_age = z_thr, k, h, max_age
        self.fresh_window, self.iso_after, self.seed = fresh_window, iso_after, seed
        self.ai_kind, self.ai_margin, self.ai_factor = ai_kind, ai_margin, ai_factor
        self.learning, self._rows, self.ai, self.ai_thr, self.ai_fit_s = False, [], None, 1.0, 0.0
        self.mu, self.med, self.sigma, self.dsig, self.eps = {}, {}, {}, {}, {}
        self.lo, self.hi, self.rate_max, self.freeze_len = {}, {}, {}, {}
        self.reset()

    # ---- state -----------------------------------------------------------
    def reset(self):
        self.last_seq, self.last_val, self.last_acc, self.cus, self.same = {}, {}, {}, {}, {}
        self.W, self.recent, self.isolated, self.isolated_at = {}, {}, set(), {}
        self.stats, self.log = Counter(), AuditLog()

    # ---- calibration on CLEAN data only ----------------------------------
    def finalize_learning(self):
        by = {}
        for sid, _, v in self._rows:
            by.setdefault(sid, []).append(v)
        for s, v in by.items():
            a = np.array(v)
            d = np.diff(a)
            ds = mad_sigma(d)
            self.mu[s], self.dsig[s], self.rate_max[s] = float(np.median(a)), float(ds), float(8 * ds)
            self.eps[s] = max(1e-12, 0.01 * ds)
            run = best = 0                       # longest natural run of (almost) equal values
            for x in d:
                run = run + 1 if abs(x) <= self.eps[s] else 0
                best = max(best, run)
            self.freeze_len[s] = max(8, 2 * best + 3)
            span = a.max() - a.min()
            self.lo[s], self.hi[s] = float(a.min() - span), float(a.max() + span)
        res = self._replay(None)
        self.med = {s: float(np.median(r)) for s, r in res.items()}
        self.sigma = {s: float(mad_sigma(r)) for s, r in res.items()}
        feats = []
        self._replay(feats)
        if len(feats) >= 200:
            t0 = perf_counter()
            X = np.array(feats)
            cut = int(0.7 * len(X))             # fit on 70%, calibrate threshold on the other 30%
            if self.ai_kind == "iforest":
                self.ai = FastIForest(seed=self.seed).fit(X[:cut])
                self.ai_thr = float(self.ai.score(X[cut:]).max() + self.ai_margin)
            else:
                self.ai = FastAutoencoder(seed=self.seed).fit(X[:cut])
                self.ai_thr = float(self.ai.score(X[cut:]).max() * self.ai_factor)
            self.ai_fit_s = perf_counter() - t0
        self.learning = False
        self.reset()

    def _replay(self, feats):
        last, acc, res = {}, {}, {}
        W = {s: Windows() for s in self.mu}
        for sid, seq, v in self._rows:
            u = v - self.mu[sid]
            oth = [x for s2, x in last.items() if s2 != sid and seq - acc[s2] <= self.max_age]
            z = None
            if len(oth) >= 2:
                r = u - statistics.median(oth)
                res.setdefault(sid, []).append(r)
                if feats is not None:
                    z = (r - self.med[sid]) / self.sigma[sid]
            w = W[sid]
            jump = abs(v - w.prev) / self.dsig[sid] if w.prev is not None else 0.0
            w.push(z, v, self.eps[sid])
            if feats is not None and z is not None:
                f = w.features(jump)
                if f is not None:
                    feats.append(f)
            last[sid], acc[sid] = u, seq
        return res

    # ---- main entry --------------------------------------------------------
    def process(self, raw: bytes, recv_time: float):
        t0 = perf_counter()
        decision, reason, sid, seq = self._decide(raw, recv_time)
        self.stats["total"] += 1
        self.stats[decision.lower()] += 1
        if not self.learning:
            self.log.append({"sid": sid, "seq": seq, "d": decision, "r": reason})
            if sid in self.sigma and reason != "sensor isolated":
                dq = self.recent.setdefault(sid, deque(maxlen=50))
                dq.append(decision != "ACCEPT")
                if self.cfg["response"] and sum(dq) >= self.iso_after and sid not in self.isolated:
                    self.isolated.add(sid)
                    self.isolated_at[sid] = seq
                    self.registry.revoked.add(sid)
        self.last_us = (perf_counter() - t0) * 1e6
        return decision, reason

    def _others(self, sid, seq):
        """Neighbour values (offset-normalised), excluding sensors not accepted recently."""
        return [x - self.mu.get(s, 0.0) for s, x in self.last_val.items()
                if s != sid and seq - self.last_acc.get(s, -99) <= self.max_age]

    def _decide(self, raw, recv_time):
        c = self.cfg
        try:
            header, v = open_packet(self.mode, raw, self.registry, verify_signature=c["signature"])
        except VerifyError as e:
            return "REJECT", str(e), "?", -1
        sid, seq, ts = header["sid"], header["seq"], header["ts"]

        if self.learning:
            self._rows.append((sid, seq, v))
            return "ACCEPT", "learning", sid, seq
        if sid not in self.sigma:
            return "REJECT", "unknown sensor", sid, seq
        if sid in self.isolated:
            return "REJECT", "sensor isolated", sid, seq

        if c["fresh"] and abs(recv_time - ts) > self.fresh_window:
            return "REJECT", "stale timestamp", sid, seq
        if c["replay"]:
            last = self.last_seq.get(sid, -1)
            if seq <= last:
                return "REJECT", "replay / old seq", sid, seq
            if last >= 0 and seq > last + 1:
                self.stats["missing"] += seq - last - 1       # silent drops become visible
            self.last_seq[sid] = seq

        # features (always computed, so any layer can be switched off independently)
        w = self.W.setdefault(sid, Windows())
        others = self._others(sid, seq)
        z = None
        if len(others) >= 2:
            z = (v - self.mu[sid] - statistics.median(others) - self.med[sid]) / self.sigma[sid]
        prev_raw = w.prev                                  # last RECEIVED value (for the freeze test)
        prev = self.last_val.get(sid) if seq - self.last_acc.get(sid, -99) <= self.max_age else None
        jump = abs(v - prev) / self.dsig[sid] if prev is not None else 0.0   # vs last ACCEPTED value
        flat = prev_raw is not None and abs(v - prev_raw) <= self.eps[sid]
        run = self.same[sid] = (self.same.get(sid, 0) + 1) if flat else 0
        w.push(z, v, self.eps[sid])
        f = w.features(jump) if z is not None else None
        pushed = z is not None

        def bad(decision, reason):
            if pushed:
                w.drop_z()
            return decision, reason, sid, seq

        if c["range"] and not (self.lo[sid] <= v <= self.hi[sid]):
            return bad("REJECT", "out of physical range")
        if c["rate"] and prev is not None and abs(v - prev) > self.rate_max[sid]:
            return bad("QUARANTINE", "implausible jump")
        if c["freeze"] and run >= self.freeze_len[sid]:
            return "QUARANTINE", "frozen value", sid, seq
        if z is not None:
            if c["neighbor"] and abs(z) > self.z_thr:
                return bad("QUARANTINE", f"disagrees with neighbours (z={z:.1f})")
            if c["cusum"]:
                zc = max(-ZCAP, min(ZCAP, z))
                hi, lo = self.cus.get(sid, (0.0, 0.0))
                hi, lo = max(0.0, hi + zc - self.k), max(0.0, lo - zc - self.k)
                hi, lo = min(hi, 2 * self.h), min(lo, 2 * self.h)     # sticky but recoverable
                self.cus[sid] = (hi, lo)
                if hi > self.h or lo > self.h:
                    return "QUARANTINE", "slow drift (CUSUM)", sid, seq
        if c["ai"] and self.ai is not None and f is not None and self.ai.score1(f) > self.ai_thr:
            return "QUARANTINE", "AI anomaly", sid, seq

        self.last_val[sid], self.last_acc[sid] = v, seq
        return "ACCEPT", "ok", sid, seq
