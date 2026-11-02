"""Fast self-test (about 20 s): python selftest.py"""
import numpy as np
from ai import FastIForest
from attacks import ChannelAttack
from crypto_layer import MODES, VerifyError, build_packet, enroll, open_packet
from evaluate import SIDS, gen_stream, process


def test_fast_iforest_matches_sklearn():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(500, 7))
    m = FastIForest(n_estimators=30, seed=1).fit(X)
    ref = -m._m.score_samples(X[:50])
    mine = m.score(X[:50])
    assert np.allclose(ref, mine, atol=1e-3), np.abs(ref - mine).max()


def test_every_mode_roundtrip_and_tamper():
    for mode in MODES:
        els, reg, _, _ = enroll(mode, SIDS)
        raw = build_packet(mode, "S01", 5, 5.0, 0.321, els["S01"])
        h, v = open_packet(mode, raw, reg)
        assert h["seq"] == 5 and abs(v - 0.321) < 1e-12, mode
        if mode == "none":
            continue
        bad = ChannelAttack("mitm_tamper", 0, 1, "S01", mode).transform(raw, "S01", 0, {})[0]
        try:
            open_packet(mode, bad, reg)
            raise AssertionError(f"tampering not detected in {mode}")
        except VerifyError:
            pass


def test_clean_traffic_has_few_false_alarms():
    for seed in (100, 101):
        r = process(gen_stream("none", seed=seed), {})
        assert r["fp"] / (r["fp"] + r["tn"]) < 0.005, r["fp"]


def test_bias_is_detected_even_with_valid_signature():
    r = process(gen_stream("ed25519", "bias", seed=100), {})
    assert r["tp"] / (r["tp"] + r["fn"]) > 0.9


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
    print("all tests passed")
