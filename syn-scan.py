#!/usr/bin/env python3

import argparse
import random
import time
from scapy.all import IP, TCP, sr1, conf
from ipaddress import ip_network
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def random_delay(min_delay, max_delay):
    time.sleep(random.uniform(min_delay, max_delay))


def syn_scan(target, port, timeout, ttl, badsum, verbose):
    packet = IP(dst=target, ttl=ttl) / TCP(dport=port, flags="S")

    if badsum:
        packet = packet.__class__(bytes(packet)[:-1] + b"\x00")

    response = sr1(packet, timeout=timeout, verbose=0)

    if response and response.haslayer(TCP):
        if response[TCP].flags == "SA":
            print(f"[+] Port {port} on {target} is open.")
        elif response[TCP].flags == "RA" and verbose: 
            print(f"[-] Port {port} on {target} is closed.")
    elif verbose:
        print(f"[-] No response for port {port} on {target}.")


def main():
    parser = argparse.ArgumentParser(description="Perform a SYN scan with Scapy.")
    parser.add_argument("network", help="Network address in CIDR notation (e.g., 192.168.0.0/24).")
    parser.add_argument("-m", "--min-delay", type=float, default=0, help="Minimum delay between packets (default: 0s).")
    parser.add_argument("-M", "--max-delay", type=float, default=0.3, help="Maximum delay between packets (default: 0.3s).")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout to wait for a response (default: 1.0s).")
    parser.add_argument("-p", "--port", type=int, help="Port to scan (if specified, scans only this port).")
    parser.add_argument("-f", "--fragment", action="store_true", help="Send fragmented packets (default: False).")
    parser.add_argument("-b", "--badsum", action="store_true", help="Send packets with invalid checksums (default: False).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity.")

    args = parser.parse_args()

    try:
        network = ip_network(args.network, strict=False)
    except ValueError:
        print("Invalid network address. Please provide a valid CIDR.")
        return

    targets = list(network.hosts())
    random.shuffle(targets)

    ports = [args.port] if args.port else list(range(1, 65536))
    random.shuffle(ports)

    if args.fragment:
        conf.frag = True

    print(f"Starting SYN scan on network: {args.network}")
    
    for target in targets:
        ttl = random.randint(1, 64)
        for port in ports:
            syn_scan(str(target), port, args.timeout, ttl, args.badsum, args.verbose)

            random_delay(args.min_delay, args.max_delay)


if __name__ == "__main__":
    main()
