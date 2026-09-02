#!/usr/bin/env python3
"""Simple command line multicast testing tool.

Python port of enclave-networks/multicast-test. Uses only the standard
library. Run on two (or more) machines: pick an interface on each, then
choose mode 1 to transmit or mode 2 to receive.

Note: don't try using interface 0 (any) to send, it won't work. Pick the
specific interface you want to test instead.
"""

import argparse
import socket
import struct
import sys
import time

DEFAULT_GROUP = "239.0.1.2"
DEFAULT_PORT = 20480
TTL = 64


def list_interfaces():
    """Return [(index, ip_string)] of local unicast addresses, 0 = any."""
    interfaces = [(0, "0.0.0.0")]
    try:
        # Primary address of the default route first, then the rest.
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip not in seen and not ip.startswith("127."):
                interfaces.append((len(interfaces), ip))
                seen.add(ip)
    except socket.gaierror:
        pass
    return interfaces


def select_interface():
    print("Interface list:\n")
    for index, ip in list_interfaces():
        label = "Any" if index == 0 else ""
        print(f"  {index:2}: {ip:<40} {label}")

    while True:
        try:
            choice = int(input("\nSelect interface: ").strip() or "0")
        except ValueError:
            continue
        interfaces = dict(list_interfaces())
        if choice in interfaces:
            return interfaces[choice]


def sender(interface_ip, group, port, count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind to the chosen interface so packets go out that NIC.
    sock.bind((interface_ip, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)
    # Allow the sender host itself to also receive its own traffic (useful
    # for a single-machine smoke test).
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    print(f"\nBound udp client to {interface_ip}. "
          f"Sending data to multicast group address {group}\n")

    sent = 0
    try:
        while True:
            message = f"Simple Multicast Testing Tool @ {time.strftime('%X')}"
            n = sock.sendto(message.encode(), (group, port))
            print(f"Message {sent:<5} sent to {group}:{port}  TTL: {TTL}  ({n} bytes)")
            sent += 1
            if count is not None and sent >= count:
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def receiver(interface_ip, group, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.bind(("", port))
    # Join the group on the chosen interface.
    mreq = struct.pack("4s4s", socket.inet_aton(group), socket.inet_aton(interface_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print(f"\nBound udp listener on {interface_ip}. Joined multicast group "
          f"{group}. Port {port}. Waiting to receive data...\n  (Ctrl+C to quit)")

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            print(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}: "
                  f"\"{data.decode(errors='replace')}\"")
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def interactive():
    print("Simple Multicast Testing Tool (python)")
    print("======================================\n")
    interface_ip = select_interface()

    print()
    group = input(f"Enter multicast address (224.0.0.0 to 239.255.255.255) "
                  f"to use [default: {DEFAULT_GROUP}]: ").strip() or DEFAULT_GROUP
    first_octet = int(group.split(".")[0]) if group.count(".") == 3 else 0
    if not (224 <= first_octet <= 239):
        sys.exit(f"Not a multicast address: {group}")

    port_raw = input(f"Enter multicast port to use (between 1 and 65535) "
                     f"[default: {DEFAULT_PORT}]: ").strip() or str(DEFAULT_PORT)
    port = int(port_raw)
    if not (1 <= port <= 65535):
        sys.exit(f"Port must be between 1 and 65535: {port}")

    print("\n    1: Multicast sender (transmit data)")
    print("    2: Multicast subscriber (listen socket, receive data)")
    print("    9: Exit\n")
    choice = input("Select action: ").strip()
    if choice == "1":
        sender(interface_ip, group, port, count=None)
    elif choice == "2":
        receiver(interface_ip, group, port)


def main():
    parser = argparse.ArgumentParser(description="Simple multicast testing tool")
    parser.add_argument("-i", "--interface", help="local IP to bind (default: 0.0.0.0)")
    parser.add_argument("-g", "--group", default=DEFAULT_GROUP,
                        help=f"multicast group (default: {DEFAULT_GROUP})")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help=f"UDP port (default: {DEFAULT_PORT})")
    parser.add_argument("-c", "--count", type=int, default=None,
                        help="sender: stop after N messages (default: forever)")
    parser.add_argument("-m", "--mode", choices=["send", "recv"],
                        help="skip the interactive prompts")
    args = parser.parse_args()

    if args.mode:
        ip = args.interface or "0.0.0.0"
        if args.mode == "send":
            sender(ip, args.group, args.port, args.count)
        else:
            receiver(ip, args.group, args.port)
    else:
        interactive()


if __name__ == "__main__":
    main()