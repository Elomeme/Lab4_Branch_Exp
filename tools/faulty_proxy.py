"""
Simple UDP proxy that injects loss/reorder for testing.

Usage:
  python faulty_proxy.py --listen 0.0.0.0:9001 --target 127.0.0.1:9000 \
      --drop 0.2 --reorder 0.1 --delay 0.05

Connect your client to the proxy port; proxy forwards to the real server.
"""

import argparse
import random
import socket
import time


def parse_hostport(value: str):
    if ":" not in value:
        raise argparse.ArgumentTypeError("must be host:port")
    host, port_s = value.rsplit(":", 1)
    return host, int(port_s)


def main():
    p = argparse.ArgumentParser(description="UDP lossy/reorder proxy")
    p.add_argument("--listen", type=parse_hostport, required=True, help="listen host:port (proxy)")
    p.add_argument("--target", type=parse_hostport, required=True, help="target host:port (real server)")
    p.add_argument("--drop", type=float, default=0.0, help="drop probability [0,1]")
    p.add_argument("--reorder", type=float, default=0.0, help="reorder probability [0,1]")
    p.add_argument("--delay", type=float, default=0.0, help="extra delay seconds for forwarded packets")
    p.add_argument("--seed", type=int, help="random seed")
    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    listen_addr = args.listen
    target_addr = args.target

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(listen_addr)
    sock.setblocking(False)

    print(f"[proxy] listening on {listen_addr}, forwarding to {target_addr}")
    print(f"[proxy] drop={args.drop} reorder={args.reorder} delay={args.delay}s")

    client_addr = None
    pending = None  # hold one packet for reordering

    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except BlockingIOError:
            # Flush pending reorder if any
            if pending:
                buf, dest = pending
                sock.sendto(buf, dest)
                pending = None
            time.sleep(0.001)
            continue

        # Determine direction
        
        if client_addr is None:
            client_addr = addr

        if addr == client_addr:
            dest = target_addr
        else:
            dest = client_addr

        # Drop
        if random.random() < args.drop:
            print("[proxy] drop packet")
            continue

        # Reorder: stash current, send previous
        if pending:
            buf, dest_prev = pending
            sock.sendto(buf, dest_prev)
            pending = None

        if random.random() < args.reorder:
            pending = (data, dest)
            print("[proxy] reorder: stash one packet")
            continue

        # Optional delay
        if args.delay > 0:
            time.sleep(args.delay)

        sock.sendto(data, dest)


if __name__ == "__main__":
    main()
