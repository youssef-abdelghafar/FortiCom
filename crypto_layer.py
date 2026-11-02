"""Provenance / integrity layer.

Protection modes (signature algorithm + optional AES-256-GCM encryption):
  none         : plain JSON, no protection (reference baseline)
  hmac         : HMAC-SHA256, one random secret PER SENSOR
  ed25519      : Ed25519 signature, trusted public-key registry
  ed25519+gcm  : Ed25519 + AES-256-GCM, session key from an X25519 handshake
  mldsa65      : ML-DSA-65 (post-quantum signature)
  mldsa65+gcm  : ML-DSA-65 + AES-256-GCM, session key from a HYBRID handshake
                 (X25519 + ML-KEM-768 -> HKDF-SHA256)

All keys are generated randomly at start-up (no key derived from a fixed name).
"""
import base64, hashlib, hmac, json, os
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MODES = ("none", "hmac", "ed25519", "ed25519+gcm", "mldsa65", "mldsa65+gcm")
RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def parts(mode):
    """mode -> (signature algorithm, uses_encryption)"""
    return mode.split("+")[0], mode.endswith("+gcm")


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


def canon(obj) -> bytes:
    """Canonical JSON: identical bytes on both sides, otherwise verification fails."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class SecureElement:
    """Software trust anchor. Private material never leaves the object; only sign()
    is exposed (emulates an HSM / TPM / secure element - no hardware needed)."""

    def __init__(self, alg):
        self.alg, self.session_key = alg, None
        if alg == "ed25519":
            self._sk = Ed25519PrivateKey.generate()
        elif alg == "mldsa65":
            self._sk = mldsa.MLDSA65PrivateKey.generate()
        elif alg == "hmac":
            self._key = os.urandom(32)
        else:
            raise ValueError(alg)

    def sign(self, msg: bytes) -> bytes:
        if self.alg == "hmac":
            return hmac.new(self._key, msg, hashlib.sha256).digest()
        return self._sk.sign(msg)

    def verifier(self):
        """What the station stores in its registry (public key; for HMAC the shared secret)."""
        return self._key if self.alg == "hmac" else self._sk.public_key()


def verify_sig(alg, material, msg: bytes, sig: bytes) -> bool:
    if alg == "hmac":
        return hmac.compare_digest(hmac.new(material, msg, hashlib.sha256).digest(), sig)
    try:
        material.verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


class Registry:
    """Trusted identities known to the ground station."""

    def __init__(self):
        self.verifier, self.session, self.revoked = {}, {}, set()


def _derive(shared: bytes, sid: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"eo-trust|" + sid.encode()).derive(shared)


class Station:
    """Ground station key material for session establishment."""

    def __init__(self, pq: bool):
        self.pq = pq
        self._x = X25519PrivateKey.generate()
        self.x_pub = self._x.public_key()
        if pq:
            self._k = mlkem.MLKEM768PrivateKey.generate()
            self.k_pub = self._k.public_key()
        self.log_element = SecureElement("ed25519")     # seals the audit log

    def accept(self, sid, hello: bytes) -> bytes:
        shared = self._x.exchange(X25519PublicKey.from_public_bytes(hello[:32]))
        if self.pq:
            shared += self._k.decapsulate(hello[32:])
        return _derive(shared, sid)


def client_hello(station: Station, sid, element: SecureElement):
    """Sensor side: ephemeral X25519 (+ ML-KEM-768 encapsulation if pq).
    The hello is signed, so a man-in-the-middle cannot swap the key exchange."""
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(station.x_pub)
    ct = b""
    if station.pq:
        kss, ct = station.k_pub.encapsulate()
        shared += kss
    element.session_key = _derive(shared, sid)
    hello = eph.public_key().public_bytes(*RAW) + ct
    return hello, element.sign(hello)


def enroll(mode, sids):
    """Create identities, registry and (for +gcm modes) per-sensor session keys."""
    alg, enc = parts(mode)
    registry, elements = Registry(), {}
    station = Station(pq=(alg == "mldsa65"))
    hs_bytes = 0
    for s in sids:
        if alg == "none":
            elements[s] = None
            continue
        el = SecureElement(alg)
        elements[s] = el
        registry.verifier[s] = el.verifier()
        if enc:
            hello, sig = client_hello(station, s, el)
            if not verify_sig(alg, registry.verifier[s], hello, sig):
                raise RuntimeError("handshake signature invalid")
            registry.session[s] = station.accept(s, hello)
            hs_bytes += len(hello) + len(sig)
    return elements, registry, station, hs_bytes


def build_packet(mode, sid, seq, ts, value, el=None) -> bytes:
    alg, enc = parts(mode)
    header = {"sid": sid, "seq": seq, "ts": ts}
    msg = {"h": header}
    if enc:
        nonce = os.urandom(12)                       # random nonce, sent with the packet
        ct = AESGCM(el.session_key).encrypt(nonce, canon({"value": value}), canon(header))
        msg["n"], msg["ct"] = b64(nonce), b64(ct)
    else:
        msg["v"] = value
    if alg != "none":
        msg["sig"] = b64(el.sign(canon(msg)))
    return json.dumps(msg, separators=(",", ":")).encode()


class VerifyError(Exception):
    pass


def open_packet(mode, raw: bytes, registry: Registry, verify_signature=True):
    """Return (header, value) or raise VerifyError(reason)."""
    alg, enc = parts(mode)
    try:
        msg = json.loads(raw)
        header = msg["h"]
        sid, seq, ts = header["sid"], header["seq"], header["ts"]
    except Exception:
        raise VerifyError("malformed packet")
    sig = msg.pop("sig", None)
    if verify_signature and alg != "none":
        if sig is None:
            raise VerifyError("missing signature")
        material = registry.verifier.get(sid)
        if material is None:
            raise VerifyError("unknown identity")
        try:
            ok = verify_sig(alg, material, canon(msg), unb64(sig))
        except Exception:
            ok = False
        if not ok:
            raise VerifyError("bad signature")
    try:
        if enc:
            key = registry.session.get(sid)
            if key is None:
                raise VerifyError("no session")
            pt = AESGCM(key).decrypt(unb64(msg["n"]), unb64(msg["ct"]), canon(header))
            value = json.loads(pt)["value"]
        else:
            value = msg["v"]
    except VerifyError:
        raise
    except InvalidTag:
        raise VerifyError("decrypt/auth failed")
    except Exception:
        raise VerifyError("malformed payload")
    return header, float(value)


class AuditLog:
    """Tamper-evident log: each entry hashes the previous one (hash chain),
    and the final head is SIGNED by the station (seal). Rewriting entries AND all
    hashes breaks the seal, which the attacker cannot forge."""

    def __init__(self):
        self.entries, self.hashes, self.seal_sig = [], [], None

    def append(self, entry: dict):
        prev = self.hashes[-1] if self.hashes else "0" * 64
        self.entries.append(entry)
        self.hashes.append(hashlib.sha256(prev.encode() + canon(entry)).hexdigest())

    def seal(self, element: SecureElement):
        if self.hashes:
            self.seal_sig = element.sign(bytes.fromhex(self.hashes[-1]))

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for e, h in zip(self.entries, self.hashes):
            if hashlib.sha256(prev.encode() + canon(e)).hexdigest() != h:
                return False
            prev = h
        return True

    def verify_seal(self, verifier) -> bool:
        return bool(self.hashes) and self.seal_sig is not None and verify_sig(
            "ed25519", verifier, bytes.fromhex(self.hashes[-1]), self.seal_sig)
