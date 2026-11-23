import struct

from constants import HeaderLength
from models import PacketStatus, ParsedTCPResponse


def parse_tcp_response(response: bytes):
    ip_payload = _strip_outer_ip(response)
    if ip_payload is None or len(ip_payload) < HeaderLength.TCP:
        return None

    try:
        tcp_data = struct.unpack("!HHLLBBHHH", ip_payload[:HeaderLength.TCP])
    except struct.error:
        return None

    server_source_port: int = tcp_data[0]
    server_dest_port: int = tcp_data[1]
    server_ack_number: int = tcp_data[3]
    server_flags: int = tcp_data[5]

    status = None
    if (server_flags & 0x12) == 0x12:
        status = PacketStatus.OPEN
    elif (server_flags & 0x04) != 0:
        status = PacketStatus.CLOSED

    if status is None:
        return None

    return ParsedTCPResponse(
        source_port=server_source_port,
        dest_port=server_dest_port,
        ack_number=server_ack_number,
        status=status
    )

def parse_icmp_response(response: bytes):
    ip_payload = _strip_outer_ip(response)
    if ip_payload is None or len(ip_payload) < HeaderLength.ICMP:
        return None

    try:
        icmp_data = struct.unpack("!BBHL", ip_payload[:HeaderLength.ICMP])
    except struct.error:
        return None

    icmp_type = icmp_data[0]
    icmp_code = icmp_data[1]
    if icmp_type != 3 or icmp_code != 3:
        return None

    if len(ip_payload) < HeaderLength.ICMP + HeaderLength.IP:
        return None

    inner_ip_len = (ip_payload[HeaderLength.ICMP] & 0x0F) * 4
    udp_start = HeaderLength.ICMP + inner_ip_len

    if len(ip_payload) < udp_start + HeaderLength.UDP:
        return None

    _, closed_port, _, _ = struct.unpack("!HHHH", ip_payload[udp_start:udp_start + HeaderLength.UDP])
    return closed_port

def _strip_outer_ip(data: bytes) -> bytes | None:
    if len(data) >= HeaderLength.IP and (data[0] >> 4) == 4:
        ip_len: int = (data[0] & 0x0F) * 4
        if len(data) < ip_len:
            return None
        return data[ip_len:]
    return None