"""
client_rush.py

Simulates a GENUINE traffic spike -- many students hitting the results
portal at once (e.g. right after results are declared) -- but from a
single, bounded, believable source host, unlike a spoofed SYN flood
which uses a huge spread of near-random source IPs.

This is what lets you test the entropy-based false-positive behaviour
of ewma_detector.py: run this alone (no attacker) and the detector
should see a high SYN rate but LOW source-IP entropy, and should NOT
trigger the defense.

Run on h1 (or h2) inside the Mininet CLI:
    h1 python3 client_rush.py
"""

import socket
import threading
import time

SERVER_IP = '10.0.0.1'   # adjust to match your server's actual IP
PORT = 8080
NUM_REQUESTS = 300
CONCURRENCY = 20


def send_one():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((SERVER_IP, PORT))
        s.send(b"GET RESULTS\n")
        s.recv(1024)
        s.close()
        return True
    except Exception:
        return False


def worker(n, results):
    ok = 0
    for _ in range(n):
        if send_one():
            ok += 1
    results.append(ok)


def main():
    print(f"[rush] Simulating a genuine result-declaration rush: "
          f"{NUM_REQUESTS} requests across {CONCURRENCY} concurrent threads, "
          f"all from this single legitimate host.")
    per_thread = NUM_REQUESTS // CONCURRENCY
    threads = []
    results = []

    start = time.time()
    for _ in range(CONCURRENCY):
        t = threading.Thread(target=worker, args=(per_thread, results))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start

    total_ok = sum(results)
    print(f"[rush] Done in {elapsed:.2f}s. {total_ok}/{NUM_REQUESTS} requests succeeded.")
    print("[rush] All requests came from this one host's IP -- the detector's "
          "source-IP entropy for this window should stay LOW even though the rate is HIGH.")


if __name__ == '__main__':
    main()
