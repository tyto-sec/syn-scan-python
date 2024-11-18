# SYN Scan Script

This Python script performs a SYN scan to identify open ports on hosts within a specified network. Using Scapy, it sends TCP SYN packets and analyzes responses to determine the state of each port. The script includes options for random delays, fragmented packets, invalid checksums, and verbose output for detailed analysis.

## Features

- **Network SYN Scan**: Scans all hosts in a given network for open ports.
- **Customizable Port Range**: Allows scanning a specific port or all ports (default: 1–65535).
- **Randomized Target and Port Order**: Shuffles the order of targets and ports to avoid predictable scanning patterns.
- **Adjustable Delays**: Configurable minimum and maximum delays between packets to manage network load.
- **Fragmented Packets**: Optionally sends fragmented packets to bypass basic firewalls.
- **Invalid Checksums**: Optionally sends packets with invalid checksums for testing IDS/IPS behavior.
- **Verbose Output**: Displays detailed results, including closed and unresponsive ports.

## Prerequisites

- **Python 3**: The script requires Python 3.
- **Scapy**: Install with `pip install scapy`.
- **Network Permissions**: Requires root or administrator privileges to send raw packets.

## Usage

Run the script with the target network in CIDR notation and optional flags to configure the scan.

```bash
sudo python3 syn_scan.py <network> [-m <min_delay>] [-M <max_delay>] [-t <timeout>] [-p <port>] [-f] [-b] [-v]
```

### Arguments

- **network**: (Required) Network address in CIDR notation (e.g., `192.168.0.0/24`).
- **-m, --min-delay**: Minimum delay between packets in seconds (default: 0).
- **-M, --max-delay**: Maximum delay between packets in seconds (default: 0.3).
- **-t, --timeout**: Timeout in seconds to wait for a response (default: 1.0).
- **-p, --port**: Specific port to scan (if omitted, scans all ports 1–65535).
- **-f, --fragment**: Send fragmented packets (default: False).
- **-b, --badsum**: Send packets with invalid checksums (default: False).
- **-v, --verbose**: Enable verbose output to show responses for all ports, including closed and unresponsive ones.

### Example

```bash
sudo python3 syn_scan.py 192.168.1.0/24 -m 0.1 -M 0.5 -t 1.0 -p 80 -f -v
```

This command performs a SYN scan on the `192.168.1.0/24` network with delays between 0.1 and 0.5 seconds, a timeout of 1 second, scanning only port 80, using fragmented packets, and enabling verbose output.

## Notes

- **Permissions**: Raw packet generation requires root privileges, so the script should be run with `sudo`.
- **Network Impact**: Adjust delays (`-m`, `-M`) to minimize the scan's impact on network performance.
- **IDS/IPS Evasion**: Options like fragmented packets (`-f`) and invalid checksums (`-b`) can be used to test detection systems.

## Author

Written by tyto.
