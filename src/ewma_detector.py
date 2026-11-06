"""
ewma_detector.py

Detects SYN flood conditions using an EWMA-tracked SYN rate combined
with Renyi entropy (order 2 / collision entropy) of source IP addresses,
plus a confirmation window before acting. Each piece is deliberate:

  - EWMA baseline: tracks "normal" SYN rate so a spike can be measured
    relative to recent history rather than one fixed number. The
    baseline update is FROZEN while a window already looks anomalous --
    otherwise an ongoing flood drags the baseline up to match itself,
    which silently disables detection after a second or two.

  - Renyi entropy over Shannon: a single real host repeatedly connecting
    produces entropy near 0; many spoofed/random source IPs push entropy
    up. Renyi (order 2) is used instead of Shannon because comparative
    literature on entropy-based SYN-flood detectors reports a lower
    false-positive rate for Renyi on this exact class of problem.

  - Confirmation window: the combined rate+entropy anomaly must persist
    for CONFIRM_WINDOWS consecutive samples before the defense activates,
    giving an explicit, tunable point on the detection-speed vs
    false-positive tradeoff instead of a single implicit threshold.

  - Closed loop: the moment an anomaly is CONFIRMED, this script calls
    directly into adaptive_syn_cookie.set_defense_state(), in the same
    process, in addition to applying an iptables rate limit.

Run on the 'server' host, ALONGSIDE server.py (in a separate terminal
inside the Mininet CLI):
    server python3 ewma_detector.py
"""

from scapy.all import sniff, TCP, IP
from collections import Counter
import math
import subprocess

import adaptive_syn_cookie as cookie_module

ALPHA_EWMA = 0.3
WINDOW_SECONDS = 1.0
SPIKE_MULTIPLIER = 3.0
MIN_BASELINE = 2.0

RENYI_ORDER = 2.0
RENYI_ENTROPY_THRESHOLD = 2.0

CONFIRM_WINDOWS = 3

ewma = 1.0
defense_active = False
_consecutive_anomalous_windows = 0

_window_src_ips = []


def packet_callback(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S" and pkt.haslayer(IP):
        _window_src_ips.append(pkt[IP].src)


def renyi_entropy(ip_list, order=RENYI_ORDER):
    if not ip_list:
        return 0.0
    counts = Counter(ip_list)
    total = len(ip_list)
    if order == 1.0:
        h = 0.0
        for c in counts.values():
            p = c / total
            h -= p * math.log2(p)
        return h
    sum_p_alpha = sum((c / total) ** order for c in counts.values())
    if sum_p_alpha <= 0:
        return 0.0
    return (1.0 / (1.0 - order)) * math.log2(sum_p_alpha)


def apply_iptables_rate_limit():
    subprocess.run([
        "iptables", "-I", "INPUT", "-p", "tcp", "--syn", "--dport", "8080",
        "-m", "limit", "--limit", "5/second", "--limit-burst", "10", "-j", "ACCEPT"
    ])
    subprocess.run([
        "iptables", "-A", "INPUT", "-p", "tcp", "--syn", "--dport", "8080", "-j", "DROP"
    ])


def clear_iptables():
    subprocess.run(["iptables", "-F"])


def main():
    global ewma, defense_active, _window_src_ips, _consecutive_anomalous_windows
    print(f"[detector] Starting EWMA-rate + Renyi-entropy detector "
          f"(order={RENYI_ORDER}, confirm_windows={CONFIRM_WINDOWS}) on port 8080...")

    while True:
        _window_src_ips = []
        sniff(filter="tcp port 8080", prn=packet_callback, timeout=WINDOW_SECONDS, store=0)

        current_rate = len(_window_src_ips) / WINDOW_SECONDS
        entropy = renyi_entropy(_window_src_ips)
        baseline = max(ewma, MIN_BASELINE)

        rate_is_anomalous = current_rate > baseline * SPIKE_MULTIPLIER
        sources_look_spoofed = entropy > RENYI_ENTROPY_THRESHOLD
        raw_anomaly = rate_is_anomalous and sources_look_spoofed

        if raw_anomaly:
            _consecutive_anomalous_windows += 1
        else:
            _consecutive_anomalous_windows = 0

        confirmed_anomaly = _consecutive_anomalous_windows >= CONFIRM_WINDOWS

        print(f"[detector] rate={current_rate:.1f}/s | ewma={ewma:.2f}/s | "
              f"renyi_entropy={entropy:.2f} bits | raw_anomaly={raw_anomaly} "
              f"({_consecutive_anomalous_windows}/{CONFIRM_WINDOWS} windows) | "
              f"confirmed={confirmed_anomaly}")

        if confirmed_anomaly and not defense_active:
            print("[detector] !!! CONFIRMED SYN flood -- activating defense !!!")
            defense_active = True
            cookie_module.set_defense_state(True)
            apply_iptables_rate_limit()

        elif rate_is_anomalous and not sources_look_spoofed and not defense_active:
            print("[detector] Rate is high but source distribution looks like a real, "
                  "bounded population -- not counted as anomalous.")

        elif not raw_anomaly and defense_active:
            print("[detector] Traffic normalized -- relaxing defense.")
            defense_active = False
            _consecutive_anomalous_windows = 0
            cookie_module.set_defense_state(False)
            clear_iptables()

        # Freeze the baseline while a window already looks anomalous, so an
        # ongoing flood can't drag the EWMA up to match itself.
        if not raw_anomaly:
            ewma = ALPHA_EWMA * current_rate + (1 - ALPHA_EWMA) * ewma


if __name__ == '__main__':
    main()
