import argparse
import ipaddress
import math
from typing import Iterator

from models import Protocol, PortTarget

MIN_PORT = 1
MAX_PORT = 65535

PortRange = tuple[Protocol, int, int]

def validate_ip_address(value: str):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {value}")

def validate_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid float value: {value}")

    if timeout > 0 and not math.isnan(timeout) and not math.isinf(timeout):
        return timeout
    else:
        raise argparse.ArgumentTypeError(f"Timeout must be positive finite number. But got: {value}")

def validate_num_threads(value: str) -> int:
    try:
        num_threads = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid int value: {value}")

    if num_threads >= 1:
        return num_threads
    else:
        raise argparse.ArgumentTypeError(f"Number of threads must be integer >= 1. But got: {value}")

def validate_port_specification(value: str) -> list[PortRange]:
    normalized = value.strip().lower()
    if '/' not in normalized:
        if normalized not in Protocol:
            raise argparse.ArgumentTypeError(f"Invalid protocol specification: {value}")
        return [(Protocol(normalized), MIN_PORT, MAX_PORT)]

    if normalized.count("/") != 1:
        raise argparse.ArgumentTypeError(f"Invalid port specification format: {value}")

    protocol_str, ports_str = normalized.split("/")
    if protocol_str not in Protocol:
        raise argparse.ArgumentTypeError(f"Invalid protocol specification: {value}")

    if not ports_str:
        raise argparse.ArgumentTypeError(f"Empty ports in: {value}")

    protocol = Protocol(protocol_str)
    ranges: list[PortRange] = []

    for chunk in ports_str.split(","):
        if not chunk:
            raise argparse.ArgumentTypeError(f"Empty port entry in: {value}")

        if "-" not in chunk:
            port = _parse_single_port(chunk)
            ranges.append((protocol, port, port))
            continue

        if chunk.count("-") != 1:
            raise argparse.ArgumentTypeError(f"Invalid port range: {chunk}")

        start_str, end_str = chunk.split("-")
        start_port = _parse_single_port(start_str)
        end_port = _parse_single_port(end_str)

        if start_port > end_port:
            raise argparse.ArgumentTypeError(
                f"Start port ({start_port}) cant be greater than end port ({end_port})"
            )

        ranges.append((protocol, start_port, end_port))

    return ranges

def _parse_single_port(raw_port: str) -> int:
    if not raw_port.isdigit():
        raise argparse.ArgumentTypeError(f"Invalid port number: {raw_port}")

    port = int(raw_port)
    if not (MIN_PORT <= port <= MAX_PORT):
        raise argparse.ArgumentTypeError(
            f"Port ({port}) must be between {MIN_PORT} and {MAX_PORT}"
        )

    return port

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        'ip_address',
        type=validate_ip_address,
        help='Target IPv4 address'
    )
    parser.add_argument(
        'ports',
        type=validate_port_specification,
        nargs='+',
        help='Ports to scan (tcp/80, udp/3000-3100 and etc.)'
    )
    parser.add_argument(
        '--timeout',
        type=validate_timeout,
        default=2.0,
        help='Response timeout in seconds (default: 2)'
    )
    parser.add_argument(
        '-j',
        '--num-threads',
        type=validate_num_threads,
        default=15,
        help='Number of threads (default: 15)'
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Verbose mode (show response time for TCP)'
    )
    parser.add_argument(
        '-g',
        '--guess',
        action='store_true',
        help='Guess application layer protocol of the port (HTTP, DNS, ECHO)'
    )

    return parser.parse_args()

def iter_target_ports(parsed_groups: list[list[PortRange]]) -> Iterator[PortTarget]:
    seen: set[tuple[Protocol, int]] = set()

    for group in parsed_groups:
        for protocol, start_port, end_port in group:
            for port in range(start_port, end_port + 1):
                key = (protocol, port)
                if key not in seen:
                    seen.add(key)
                    yield PortTarget(port=port, protocol=protocol)
