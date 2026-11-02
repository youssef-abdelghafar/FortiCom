"""End-to-end simulation + metrics.

    python evaluate.py                 # full evaluation (synthetic data, 10 held-out seeds)
    python evaluate.py --quick         # 3 seeds, fast sanity run
    python evaluate.py --csv data.csv  # your dataset (wide CSV, one numeric column per sensor)
    python evaluate.py --only T3 T5    # only some tables

Method (honesty rules)
  * Detector parameters were tuned on DEV seeds 0-4 using the DEV attacks only.
  * Final numbers use TEST seeds 100-109 and include HELD-OUT attack families.
  * Calibration uses clean data only. Packet generation (sensor side) is separated from
    receiver processing, so timing and memory are measured on the receiver alone.
"""
import argparse, csv, os, sys, time, tracemalloc
from concurrent.futures import ProcessPoolExecutor
import numpy as np
from attacks import (CHANNEL_ATTACKS, DEV_ATTACKS, HELD_OUT, SENSOR_ATTACKS,
                     ChannelAttack, SensorAttack)
from crypto_layer import MODES, build_packet, enroll
from data import load_csv, synthetic
from receiver import STAT_LAYERS, Receiver, mad_sigma

SIDS = [f"S0{i + 1}" for i in range(5)]
VICTIM = "S03"
TEST_SEEDS = list(range(100, 110))
NO_STATS = {l: False for l in STAT_LAYERS}


# ---------------------------------------------------------------- generation
def gen_stream(mode, sensor_attack="none", channel_attack="none", seed=0,
               n_train=300, steps=600, csv_path=None):
    """Sensor side + channel: returns all packets exactly as the receiver gets them."""
    rng = np.random.default_rng(seed + 7)
    if csv_path:
        X_all = load_csv(csv_path, n=len(SIDS))
        n_train = len(X_all) // 3
        X_train, X = X_all[:n_train], X_all[n_train:]
        steps = len(X)
    else:
        full = synthetic(n_train + steps, len(SIDS), seed)
        X_train, X = full[:n_train], full[n_train:]
    atk_start = steps // 2
    vi = SIDS.index(VICTIM)
    res = X_train[:, vi] - np.median(np.delete(X_train, vi, axis=1), axis=1)
    sigma = mad_sigma(res - np.median(res))

    elements, registry, station, hs_bytes = enroll(mode, SIDS)
    train = [(build_packet(mode, s, t, float(t), float(X_train[t, i]), elements[s]), t + 0.05)
             for t in range(n_train) for i, s in enumerate(SIDS)]

    sat = SensorAttack(sensor_attack, atk_start, sigma, rng)
    chan = ChannelAttack(channel_attack, atk_start, 5, VICTIM, mode)
    hist, archive, test, dropped = [], {s: [] for s in SIDS}, [], 0
    for t in range(steps):
        for i, s in enumerate(SIDS):
            v, atk = float(X[t, i]), False
            if s == VICTIM:
                hist.append(v)
                atk = sat.is_attack(t)
                v = sat.apply(t, v, hist)
            raw = build_packet(mode, s, t, float(t), v, elements[s])
            archive[s].append(raw)
            raw2, atk2 = chan.transform(raw, s, t, archive)
            if raw2 is None:
                dropped += 1
                continue
            test.append((raw2, t + 0.05, atk or atk2, t))
    return dict(train=train, test=test, registry=registry, station=station, hs_bytes=hs_bytes,
                atk_start=atk_start, dropped=dropped, mode=mode)


# ---------------------------------------------------------------- processing
def process(stream, cfg=None, **rxkw):
    cfg = dict(cfg or {})
    if "ai_kind" in cfg:                       # receiver option passed through the config dict
        rxkw["ai_kind"] = cfg.pop("ai_kind")
    rx = Receiver(stream["mode"], stream["registry"], cfg, **rxkw)
    rx.learning = True
    for raw, t in stream["train"]:
        rx.process(raw, t)
    rx.finalize_learning()
    labels, alerts, steps, recv_us, nbytes = [], [], [], 0.0, 0
    for raw, t, lab, step in stream["test"]:
        d, _ = rx.process(raw, t)
        recv_us += rx.last_us
        nbytes += len(raw)
        labels.append(lab)
        alerts.append(d != "ACCEPT")
        steps.append(step)
    L, A = np.array(labels), np.array(alerts)
    tp, fn = int((L & A).sum()), int((L & ~A).sum())
    fp, tn = int((~L & A).sum()), int((~L & ~A).sum())
    det = [steps[j] for j in range(len(L)) if L[j] and A[j]]
    n = max(1, len(L))
    return dict(tp=tp, fn=fn, fp=fp, tn=tn, n=len(L),
                latency=(det[0] - stream["atk_start"]) if det else None,
                recv_us=recv_us / n, bytes=nbytes / n, dropped=stream["dropped"],
                missing=int(rx.stats["missing"]), ai_fit_s=rx.ai_fit_s,
                victim_isolated=VICTIM in rx.isolated,
                clean_isolated=len([s for s in rx.isolated if s != VICTIM]), rx=rx)


def job(args):
    """One (attack, seed) = one generated stream, processed under several configs."""
    mode, kind, name, seed, cfgs, kw = args
    s = gen_stream(mode, name if kind == "sensor" else "none",
                   name if kind == "channel" else "none", seed, **kw)
    out = []
    for cfg in cfgs:
        r = process(s, cfg)
        r.pop("rx")
        out.append(r)
    return out


def run_group(pool, mode, kind, names, seeds, cfgs, kw):
    """-> {name: [per-config list of per-seed result dicts]}"""
    tasks = [(mode, kind, nm, sd, cfgs, kw) for nm in names for sd in seeds]
    res = list(pool.map(job, tasks)) if pool else [job(t) for t in tasks]
    out, i = {}, 0
    for nm in names:
        per = res[i:i + len(seeds)]
        i += len(seeds)
        out[nm] = [[per[s][c] for s in range(len(seeds))] for c in range(len(cfgs))]
    return out


# ---------------------------------------------------------------- statistics
def mean_ci(xs):
    xs = [x for x in xs if x is not None and x == x]
    if not xs:
        return float("nan"), 0.0
    m = float(np.mean(xs))
    return m, (1.96 * float(np.std(xs, ddof=1)) / np.sqrt(len(xs)) if len(xs) > 1 else 0.0)


def pm(xs, p=2):
    m, h = mean_ci(xs)
    return "-" if m != m else f"{m:.{p}f}±{h:.{p}f}"


def per_seed(runs, key):
    f = {"recall": lambda r: r["tp"] / (r["tp"] + r["fn"]) if r["tp"] + r["fn"] else None,
         "precision": lambda r: r["tp"] / (r["tp"] + r["fp"]) if r["tp"] + r["fp"] else None,
         "far": lambda r: r["fp"] / (r["fp"] + r["tn"]) if r["fp"] + r["tn"] else None,
         "exposure": lambda r: r["fn"]}[key]
    return [f(r) for r in runs]


def lat_str(runs):
    d = [r["latency"] for r in runs if r["latency"] is not None]
    return f"{int(np.median(d))} ({len(d)}/{len(runs)} runs)" if d else f"never (0/{len(runs)} runs)"


def table(title, header, rows, out):
    print(f"\n### {title}")
    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * len(header))
    for r in rows:
        print("| " + " | ".join(map(str, r)) + " |")
    sys.stdout.flush()
    name = title.split(":")[0].strip().replace(" ", "_")
    with open(os.path.join(out, name + ".csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


# ---------------------------------------------------------------- tables
def t1_primitives(out):
    """Pure cryptographic primitives, no JSON / logging around them."""
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from crypto_layer import RAW
    import hashlib, hmac
    msg, n = os.urandom(100), 300

    def bench(f):
        t = time.perf_counter()
        for _ in range(n):
            f()
        return (time.perf_counter() - t) / n * 1e6
    rows = []
    key = os.urandom(32)
    tag = hmac.new(key, msg, hashlib.sha256).digest()
    rows.append(["HMAC-SHA256", "32 B tag", f"{bench(lambda: hmac.new(key, msg, hashlib.sha256).digest()):.1f}",
                 f"{bench(lambda: hmac.compare_digest(hmac.new(key, msg, hashlib.sha256).digest(), tag)):.1f}"])
    e = Ed25519PrivateKey.generate(); es = e.sign(msg); ep = e.public_key()
    rows.append(["Ed25519", f"sig {len(es)} B, pub {len(ep.public_bytes(*RAW))} B",
                 f"{bench(lambda: e.sign(msg)):.1f}", f"{bench(lambda: ep.verify(es, msg)):.1f}"])
    m = mldsa.MLDSA65PrivateKey.generate(); ms = m.sign(msg); mp = m.public_key()
    rows.append(["ML-DSA-65 (post-quantum)", f"sig {len(ms)} B, pub {len(mp.public_bytes(*RAW))} B",
                 f"{bench(lambda: m.sign(msg)):.1f}", f"{bench(lambda: mp.verify(ms, msg)):.1f}"])
    a = AESGCM(os.urandom(32)); nonce = os.urandom(12); ct = a.encrypt(nonce, msg, None)
    rows.append(["AES-256-GCM", f"+{len(ct) - len(msg)} B tag, +12 B nonce",
                 f"{bench(lambda: a.encrypt(nonce, msg, None)):.1f}", f"{bench(lambda: a.decrypt(nonce, ct, None)):.1f}"])
    k = mlkem.MLKEM768PrivateKey.generate(); kp = k.public_key(); ss, kct = kp.encapsulate()
    rows.append(["ML-KEM-768 (post-quantum key exchange)", f"ct {len(kct)} B, pub {len(kp.public_bytes(*RAW))} B",
                 f"{bench(lambda: kp.encapsulate()):.1f}", f"{bench(lambda: k.decapsulate(kct)):.1f}"])
    x = X25519PrivateKey.generate(); xp = X25519PrivateKey.generate().public_key()
    rows.append(["X25519 (classical key exchange)", "pub 32 B", f"{bench(lambda: x.exchange(xp)):.1f}",
                 f"{bench(lambda: x.exchange(xp)):.1f}"])
    table("T1: cryptographic primitives (pure operation, 100-byte message, one core)",
          ["primitive", "sizes", "sign / encrypt / encapsulate (us)", "verify / decrypt / decapsulate (us)"], rows, out)


def t1b_modes(out, kw):
    """Per-message cost of each protection mode, measured on the receiver alone."""
    rows = []
    cfg = {"ai": False}
    process(gen_stream("none", seed=99, **kw), cfg)          # warm-up (library start-up costs)
    for m in MODES:
        s = gen_stream(m, seed=100, **kw)
        r = process(s, cfg)
        s2 = gen_stream(m, seed=100, **kw)           # same traffic again for the memory pass
        tracemalloc.start()
        process(s2, cfg)
        peak = tracemalloc.get_traced_memory()[1] / 1024
        tracemalloc.stop()
        rows.append([m, f"{r['bytes']:.0f}", f"{r['recv_us']:.0f}", f"{peak:.0f}", s["hs_bytes"],
                     f"{r['fp'] / max(1, r['fp'] + r['tn']):.4f}"])
    table("T1b: protection modes on clean traffic (receiver side, statistical layers on, AI off)",
          ["mode", "bytes / message on the wire", "receiver us / message", "receiver peak memory KB",
           "handshake bytes (5 sensors)", "false-alarm rate"], rows, out)


def t2_channel(pool, out, seeds, kw):
    kw2 = dict(kw, n_train=150, steps=300) if not kw.get("csv_path") else kw
    only_sig = dict(NO_STATS, ai=False, fresh=False, replay=False)
    only_prov = dict(NO_STATS, ai=False)
    rows = []
    for ca in CHANNEL_ATTACKS[:3]:
        row = [ca]
        for m in MODES:
            r = run_group(pool, m, "channel", [ca], seeds, [only_sig], kw2)[ca][0]
            row.append(pm(per_seed(r, "recall"), 2))
        r = run_group(pool, "ed25519", "channel", [ca], seeds, [only_prov], kw2)[ca][0]
        row.append(pm(per_seed(r, "recall"), 2))
        rows.append(row)
    table("T2: man-in-the-middle recall - signature check ONLY, per mode "
          "(last column: ed25519 + timestamp + sequence number, statistics off)",
          ["attack"] + list(MODES) + ["ed25519 + fresh + replay"], rows, out)


def t3_full(pool, out, seeds, kw):
    cfg = {}
    rows = []
    groups = [("dev", DEV_ATTACKS, "sensor"), ("held-out", HELD_OUT, "sensor"),
              ("channel", CHANNEL_ATTACKS[:3], "channel")]
    for split, names, kind in groups:
        res = run_group(pool, "ed25519", kind, names, seeds, [cfg], kw)
        for nm in names:
            r = res[nm][0]
            rows.append([nm, "compromised sensor" if kind == "sensor" else "man-in-the-middle", split,
                         pm(per_seed(r, "recall")), pm(per_seed(r, "precision")),
                         pm(per_seed(r, "far"), 4), lat_str(r), f"{np.mean([x['fn'] for x in r]):.0f}"])
    table("T3: full pipeline (ed25519, all layers incl. AI), test seeds, mean ± 95% CI",
          ["attack", "class", "split", "recall", "precision", "false-alarm rate",
           "median latency steps (detected runs)", "bad messages accepted (mean)"], rows, out)


def t4_ablation(pool, out, seeds, kw):
    layers = list(STAT_LAYERS) + ["ai"]
    cfgs = [{}] + [{l: False} for l in layers]
    res = run_group(pool, "none", "sensor", SENSOR_ATTACKS, seeds, cfgs, kw)
    rows = [[nm] + [pm(per_seed(res[nm][c], "recall")) for c in range(len(cfgs))] for nm in SENSOR_ATTACKS]
    table("T4: ablation - recall when ONE layer is removed (mode none: crypto cannot help here)",
          ["attack", "all layers"] + [f"no {l}" for l in layers], rows, out)


def t4b_alone(pool, out, seeds, kw):
    layers = list(STAT_LAYERS) + ["ai"]
    cfgs = [dict({l: False for l in layers}, **{l: True}) for l in layers]
    res = run_group(pool, "none", "sensor", SENSOR_ATTACKS, seeds, cfgs, kw)
    rows = [[nm] + [pm(per_seed(res[nm][c], "recall")) for c in range(len(cfgs))] for nm in SENSOR_ATTACKS]
    table("T4b: each layer ALONE - recall (shows what each layer contributes by itself)",
          ["attack"] + [f"only {l}" for l in layers], rows, out)


def t5_ai(pool, out, seeds, kw):
    cfgs = [{"ai": False}, dict(NO_STATS, ai=True, ai_kind="iforest"), dict(NO_STATS, ai=True), {}]
    res = run_group(pool, "none", "sensor", SENSOR_ATTACKS, seeds, cfgs, kw)
    rows = [[nm] + [pm(per_seed(res[nm][c], "recall")) for c in range(4)] for nm in SENSOR_ATTACKS]
    far = [pm([x for nm in SENSOR_ATTACKS for x in per_seed(res[nm][c], "far")], 4) for c in range(4)]
    rows.append(["false-alarm rate (all runs)"] + far)
    table("T5: statistics vs AI models - recall (AI-only rows switch every statistical layer off)",
          ["attack", "statistics only", "Isolation Forest only", "Autoencoder only", "statistics + Autoencoder"],
          rows, out)
    s = gen_stream("none", seed=seeds[0], **kw)
    rx = process(s, {})["rx"]
    t0 = time.perf_counter()
    f = [0.0] * 7
    for _ in range(2000):
        rx.ai.score1(f)
    us = (time.perf_counter() - t0) / 2000 * 1e6
    print(f"\nAI cost (autoencoder): training {rx.ai_fit_s:.2f} s once, scoring {us:.0f} us per message")


def t6_response(pool, out, seeds, kw):
    names = ("bias", "drift", "slow_bias", "noise", "evasion")
    cfgs = [{}, {"response": True}]
    res = run_group(pool, "none", "sensor", names, seeds, cfgs, kw)
    rows = []
    for nm in names:
        a, b = res[nm]
        rows.append([nm, f"{np.mean([x['fn'] for x in a]):.0f}", f"{np.mean([x['fn'] for x in b]):.0f}",
                     f"{sum(x['victim_isolated'] for x in b)}/{len(b)}", sum(x["clean_isolated"] for x in b)])
    table("T6: automatic response (isolate a sensor after 15 alerts in its last 50 messages)",
          ["attack", "bad messages accepted, no response", "bad messages accepted, with response",
           "attacked sensor isolated (runs)", "clean sensors wrongly isolated (all runs)"], rows, out)


def t7_drop(pool, out, seeds, kw):
    res = run_group(pool, "ed25519", "channel", ["mitm_drop"], seeds, [{}], kw)["mitm_drop"][0]
    rows = [["mitm_drop", f"{np.mean([r['dropped'] for r in res]):.0f}",
             f"{np.mean([r['missing'] for r in res]):.0f}",
             f"{sum(r['missing'] >= r['dropped'] - 1 for r in res)}/{len(res)}"]]
    table("T7: silent message loss (messages dropped by the attacker vs gaps counted by the receiver)",
          ["attack", "messages dropped (mean)", "gaps detected (mean)", "runs where all gaps were seen"], rows, out)


def audit_demo():
    s = gen_stream("ed25519", "bias", seed=100)
    r = process(s, {})
    rx, st = r["rx"], s["station"]
    rx.log.seal(st.log_element)
    pub = st.log_element.verifier()
    ok1 = rx.log.verify_chain() and rx.log.verify_seal(pub)
    j = next(i for i, x in enumerate(rx.log.entries) if x["d"] != "ACCEPT")
    rx.log.entries[j]["d"] = "ACCEPT"                        # attacker rewrites one alert...
    import hashlib
    from crypto_layer import canon
    prev = "0" * 64                                          # ...and recomputes every hash
    for i, e in enumerate(rx.log.entries):
        prev = hashlib.sha256(prev.encode() + canon(e)).hexdigest()
        rx.log.hashes[i] = prev
    print(f"\nAudit log: intact -> chain+seal valid: {ok1}. After rewriting an entry and ALL hashes: "
          f"chain valid: {rx.log.verify_chain()}, seal valid: {rx.log.verify_seal(pub)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--out", default="results")
    ap.add_argument("--only", nargs="*", default=[])
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    seeds = TEST_SEEDS[:3] if a.quick else TEST_SEEDS[:a.seeds]
    if a.csv:
        seeds = [0]
    kw = dict(csv_path=a.csv)
    want = lambda t: not a.only or t in a.only
    pool = ProcessPoolExecutor(a.jobs) if a.jobs > 1 else None
    t0 = time.time()
    print(f"test seeds: {seeds}  | parallel jobs: {a.jobs}")
    if want("T1"):
        t1_primitives(a.out)
        t1b_modes(a.out, kw)
    if want("T2"):
        t2_channel(pool, a.out, seeds[:3], kw)
    if want("T3"):
        t3_full(pool, a.out, seeds, kw)
    if want("T4"):
        t4_ablation(pool, a.out, seeds[:5], kw)
    if want("T4"):
        t4b_alone(pool, a.out, seeds[:5], kw)
    if want("T5"):
        t5_ai(pool, a.out, seeds[:5], kw)
    if want("T6"):
        t6_response(pool, a.out, seeds[:5], kw)
    if want("T7"):
        t7_drop(pool, a.out, seeds, kw)
    if want("T8"):
        audit_demo()
    print(f"\nTotal time: {time.time() - t0:.0f} s")


if __name__ == "__main__":
    main()
