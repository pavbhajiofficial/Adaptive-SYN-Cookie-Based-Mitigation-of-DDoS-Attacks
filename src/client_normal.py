"""
client_normal.py
Simulates a legitimate student repeatedly checking the exam-results portal.
Run on h1 or h2 inside the Mininet CLI:
    h1 python3 client_normal.py
"""

import socket
import time
import random

SERVER_IP = 'server'  # Mininet resolves host names; falls back to a fixed IP below if that fails
PORT = 8080
NUM_REQUESTS = 20


def resolve_server_ip():
    try:
        return socket.gethostbyname(SERVER_IP)
    except Exception:
        return '10.0.0.1'  # adjust if your server host gets a different IP (check with: server ifconfig)


def send_request(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        start = time.time()
        s.connect((ip, PORT))
        s.send(b"GET RESULTS\n")
        data = s.recv(1024)
        elapsed = (time.time() - start) * 1000
        print(f"[client] Response: {data.strip()} | RTT: {elapsed:.2f} ms")
        s.close()
        return True
    except Exception as e:
        print(f"[client] Request failed: {e}")
        return False


def main():
    ip = resolve_server_ip()
    print(f"[client] Sending {NUM_REQUESTS} requests to {ip}:{PORT}")
    success = 0
    for i in range(NUM_REQUESTS):
        if send_request(ip):
            success += 1
        time.sleep(random.uniform(0.5, 2.0))  # realistic, bursty-but-not-flooding behaviour
    print(f"[client] Done. {success}/{NUM_REQUESTS} succeeded.")


if __name__ == '__main__':
    main()
