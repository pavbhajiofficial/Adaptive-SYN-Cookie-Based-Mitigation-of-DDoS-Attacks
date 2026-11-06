"""
adaptive_syn_cookie.py

Core protocol-side piece of this project. Builds on a standard TCP SYN
cookie in three ways:

  1. ADAPTIVE ROTATION tied to a live detection signal: the secret key
     rotates faster while an attack is CONFIRMED, slower during normal
     load, instead of on a fixed schedule.

  2. REPLAY RESISTANCE in the same mechanism: HMAC-SHA256 with a
     per-connection nonce and a short validity window, with a cache of
     already-used nonces so a captured/replayed cookie cannot be reused.

  3. CLOSED-LOOP HOOK: set_defense_state() is called directly by
     ewma_detector.py the instant it confirms an anomaly, so detection
     output immediately reconfigures cookie generation in the same
     process, rather than through an indirect side channel.

NOTE: this is a conceptual/standalone demonstration of the algorithm --
it does not replace or patch the Linux kernel's real TCP stack.
"""

import hmac
import hashlib
import time
import random

# --- Configuration ---
NORMAL_ROTATION_INTERVAL = 60   # seconds; secret key lifetime under normal load
ATTACK_ROTATION_INTERVAL = 5    # seconds; secret key lifetime while defense_active
COOKIE_VALID_WINDOW = 30        # seconds; how long a cookie is accepted after issue
NONCE_CACHE_LIMIT = 5000        # cap on remembered nonces to bound memory use

_secret_key = str(random.getrandbits(128)).encode()
_last_rotation = time.time()
_defense_active = False
_used_nonces = set()


def set_defense_state(active: bool):
    """Called by ewma_detector.py the instant it flags/clears an anomaly."""
    global _defense_active
    if active != _defense_active:
        print(f"[cookie] Defense state changed -> defense_active={active}")
    _defense_active = active


def _get_rotation_interval():
    return ATTACK_ROTATION_INTERVAL if _defense_active else NORMAL_ROTATION_INTERVAL


def _maybe_rotate_secret():
    global _secret_key, _last_rotation
    interval = _get_rotation_interval()
    if time.time() - _last_rotation >= interval:
        _secret_key = str(random.getrandbits(128)).encode()
        _last_rotation = time.time()
        print(f"[cookie] Secret key rotated (interval={interval}s, defense_active={_defense_active})")


def _remember_nonce(nonce):
    if len(_used_nonces) >= NONCE_CACHE_LIMIT:
        _used_nonces.pop()  # crude eviction; fine for a demo-scale cache
    _used_nonces.add(nonce)


def generate_cookie(src_ip, src_port, dst_ip, dst_port):
    """
    Returns (cookie, nonce, timestamp).
    cookie = truncated HMAC-SHA256(secret, src_ip|dst_ip|src_port|dst_port|nonce|timestamp|state_bit)
    """
    _maybe_rotate_secret()

    nonce = random.getrandbits(32)
    timestamp = int(time.time())
    state_bit = "1" if _defense_active else "0"

    msg = f"{src_ip}{dst_ip}{src_port}{dst_port}{nonce}{timestamp}{state_bit}".encode()
    digest = hmac.new(_secret_key, msg, hashlib.sha256).hexdigest()
    cookie = int(digest, 16) % (2 ** 24)

    return cookie, nonce, timestamp


def verify_cookie(cookie, nonce, timestamp, src_ip, src_port, dst_ip, dst_port):
    """
    Recomputes the expected cookie for both possible state_bits, checks the
    time window, and rejects outright if the nonce has already been used.
    """
    if time.time() - timestamp > COOKIE_VALID_WINDOW:
        return False, "expired"

    if nonce in _used_nonces:
        return False, "replay_detected"

    for state_bit in ("0", "1"):
        msg = f"{src_ip}{dst_ip}{src_port}{dst_port}{nonce}{timestamp}{state_bit}".encode()
        digest = hmac.new(_secret_key, msg, hashlib.sha256).hexdigest()
        expected = int(digest, 16) % (2 ** 24)
        if cookie == expected:
            _remember_nonce(nonce)
            return True, f"valid (state_bit={state_bit})"

    return False, "invalid"


if __name__ == '__main__':
    # --- Demonstration ---
    src_ip, src_port = "10.0.0.5", 51000
    dst_ip, dst_port = "10.0.0.1", 8080

    print("=== Normal traffic scenario ===")
    set_defense_state(False)
    cookie, nonce, ts = generate_cookie(src_ip, src_port, dst_ip, dst_port)
    print(f"Generated cookie={cookie}, nonce={nonce}, ts={ts}")
    ok, reason = verify_cookie(cookie, nonce, ts, src_ip, src_port, dst_ip, dst_port)
    print(f"First verification: {ok} ({reason})")

    print("\n--- Attempting to REPLAY the same cookie ---")
    ok2, reason2 = verify_cookie(cookie, nonce, ts, src_ip, src_port, dst_ip, dst_port)
    print(f"Replay verification: {ok2} ({reason2})  <-- should be rejected")

    print("\n=== Attack scenario (defense_active=True) ===")
    set_defense_state(True)
    cookie2, nonce2, ts2 = generate_cookie(src_ip, src_port, dst_ip, dst_port)
    print(f"Generated cookie={cookie2}, nonce={nonce2}, ts={ts2}")
    ok3, reason3 = verify_cookie(cookie2, nonce2, ts2, src_ip, src_port, dst_ip, dst_port)
    print(f"Verification under attack state: {ok3} ({reason3})")
