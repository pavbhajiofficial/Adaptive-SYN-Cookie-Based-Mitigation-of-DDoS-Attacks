"""
server.py
A minimal TCP server simulating the campus exam-results portal.
Run this on the 'server' host inside the Mininet CLI:
    server python3 server.py
"""

import socket
import threading

HOST = '0.0.0.0'
PORT = 8080

served_count = 0
lock = threading.Lock()


def handle_client(conn, addr):
    global served_count
    try:
        conn.settimeout(5)
        conn.recv(1024)  # read whatever the client sends, ignore content
        response = b"Results: PASS\n"
        conn.send(response)
        with lock:
            served_count += 1
    except Exception:
        pass
    finally:
        conn.close()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(50)  # backlog size -- deliberately small so a SYN flood's effect is visible
    print(f"[server] Exam portal listening on {HOST}:{PORT} (backlog=50)")

    try:
        while True:
            conn, addr = s.accept()
            print(f"[server] Connection accepted from {addr}, total served={served_count}")
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[server] Shutting down.")
    finally:
        s.close()


if __name__ == '__main__':
    main()
