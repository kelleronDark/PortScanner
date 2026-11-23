import socket
import struct

from models import AppProtocol

ECHO_PAYLOAD = b"ECHO_PROBE\r\n"
HTTP_PAYLOAD = b"HEAD / HTTP/1.0\r\n\r\n"

DNS_TX_ID = b"\x12\x34"
DNS_QUERY = (
    DNS_TX_ID
    + b"\x01\x00"
    + b"\x00\x01"
    + b"\x00\x00"
    + b"\x00\x00"
    + b"\x00\x00"
    + b"\x07example\x03com\x00"
    + b"\x00\x01"
    + b"\x00\x01"
)


def _is_valid_dns_response(data: bytes) -> bool:
    if len(data) < 12:
        return False
    tx_id_matches = data[:2] == DNS_TX_ID
    is_response_flag = (data[2] & 0x80) != 0
    return tx_id_matches and is_response_flag

def _probe_tcp_echo(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(ECHO_PAYLOAD)
            response = sock.recv(512)
            return response == ECHO_PAYLOAD
    except OSError:
        return False

def _probe_tcp_http(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(HTTP_PAYLOAD)
            response = sock.recv(512)
            return response.startswith(b"HTTP/")
    except OSError:
        return False

def _probe_tcp_dns(ip: str, port: int, timeout: float) -> bool:
    tcp_dns_payload = struct.pack("!H", len(DNS_QUERY)) + DNS_QUERY
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(tcp_dns_payload)
            response = sock.recv(512)
            if len(response) < 14:
                return False
            return _is_valid_dns_response(response[2:])
    except OSError:
        return False

def _probe_udp_echo(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(ECHO_PAYLOAD, (ip, port))
            response, sender_addr = sock.recvfrom(512)
            return sender_addr[0] == ip and sender_addr[1] == port and response == ECHO_PAYLOAD
    except OSError:
        return False

def _probe_udp_dns(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(DNS_QUERY, (ip, port))
            response, sender_addr = sock.recvfrom(512)
            return (
                sender_addr[0] == ip
                and sender_addr[1] == port
                and _is_valid_dns_response(response)
            )
    except OSError:
        return False

def guess_tcp_protocol(ip: str, port: int, timeout: float) -> AppProtocol | None:
    if _probe_tcp_echo(ip, port, timeout):
        return AppProtocol.ECHO
    if _probe_tcp_http(ip, port, timeout):
        return AppProtocol.HTTP
    if _probe_tcp_dns(ip, port, timeout):
        return AppProtocol.DNS
    return None

def guess_udp_protocol(ip: str, port: int, timeout: float) -> AppProtocol | None:
    if _probe_udp_echo(ip, port, timeout):
        return AppProtocol.ECHO
    if _probe_udp_dns(ip, port, timeout):
        return AppProtocol.DNS
    return None
