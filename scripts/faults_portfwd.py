#!/usr/bin/env python3
"""Port bridge for the partition scenarios of scripts/phase6_faults.py (see `Net` in
scripts/faults_env.py).

The custody stack (mpc-node, relays, signers, mpc-sign, provisioning) runs in the host
namespaces as the ordinary user, as in production; only the conductors run inside the
per-node network namespaces. A conductor's admin and app ports are bridged to the same
port numbers on the host loopback through unix sockets in a private (0700) directory:

  host 127.0.0.1:P  --(--side host)-->  <dir>/P.sock  --(--side ns)-->  node netns 127.0.0.1:P

The bridge copies bytes only; it never parses or logs payloads. DISPOSABLE harness only.
Usage: faults_portfwd.py --side host|ns --dir DIR --ports P[,P...]
"""
from __future__ import annotations
import argparse, socket, threading
from pathlib import Path


def pump(src: socket.socket, dst: socket.socket):
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock, how in ((dst, socket.SHUT_WR), (src, socket.SHUT_RD)):
            try:
                sock.shutdown(how)
            except OSError:
                pass


def bridge(conn: socket.socket, connect):
    try:
        upstream = connect()
    except OSError:
        conn.close()
        return
    back = threading.Thread(target=pump, args=(upstream, conn), daemon=True)
    back.start()
    pump(conn, upstream)
    back.join()
    conn.close()
    upstream.close()


def serve(listener: socket.socket, connect):
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=bridge, args=(conn, connect), daemon=True).start()


def tcp(port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(None)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def unix(path: Path) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(path))
    return sock


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--side", choices=("host", "ns"), required=True)
    ap.add_argument("--dir", type=Path, required=True)
    ap.add_argument("--ports", required=True)
    a = ap.parse_args()
    ports = [int(p) for p in a.ports.split(",")]
    for port in ports:
        path = a.dir / f"{port}.sock"
        if a.side == "host":
            listener = socket.create_server(("127.0.0.1", port))
            connect = lambda path=path: unix(path)
        else:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(64)
            connect = lambda port=port: tcp(port)
        threading.Thread(target=serve, args=(listener, connect), daemon=True).start()
    print(f"bridge ready: side={a.side} ports={','.join(map(str, ports))}", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
