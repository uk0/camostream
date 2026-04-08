#!/usr/bin/env python3
"""Persistent TCP echo server - echoes back each line received."""
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4141

def handle_client(conn, addr):
    try:
        data = conn.recv(4096)
        if data:
            conn.sendall(data)
    finally:
        conn.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', PORT))
sock.listen(5)
sys.stdout.write(f"TCP echo listening on 127.0.0.1:{PORT}\n")
sys.stdout.flush()

while True:
    try:
        conn, addr = sock.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()
    except KeyboardInterrupt:
        break
    except:
        break

sock.close()
